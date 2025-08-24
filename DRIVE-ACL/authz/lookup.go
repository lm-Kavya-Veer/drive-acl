package authz

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

// Node represents a generic resource with children
type Node struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Children []*Node `json:"children,omitempty"`
}

// ListResourceHierarchy returns a hierarchical tree of resources for any subject
func ListResourceHierarchy(resourceType, permission, subjectType, subjectID string) []*Node {
	ctx := context.Background()

	// Step 1: Lookup all accessible resources for the subject
	resp, err := Client.LookupResources(ctx, &v1.LookupResourcesRequest{
		ResourceObjectType: resourceType,
		Permission:         permission,
		Subject: &v1.SubjectReference{
			Object: &v1.ObjectReference{
				ObjectType: subjectType,
				ObjectId:   subjectID,
			},
		},
	})
	if err != nil {
		log.Printf("failed to lookup resources: %v", err)
		return nil
	}

	type item struct {
		id     string
		parent string
	}

	rawItems := []item{}
	resourceIDs := []string{}

	// Collect all resource IDs
	for {
		r, err := resp.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("error receiving resource: %v", err)
			break
		}
		resourceIDs = append(resourceIDs, r.ResourceObjectId)
	}

	// Step 2: Read parent relationships for these resources
	parentResp, err := Client.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType:     resourceType,
			OptionalRelation: "parent",
		},
	})
	if err != nil {
		log.Printf("failed to read parent relationships: %v", err)
		return nil
	}
	fmt.Println("Parent relationships:")
	fmt.Println(parentResp.Recv())
	// Map: child -> parent
	parentMap := make(map[string]string)
	for {
		rel, err := parentResp.Recv()
		if err != nil {
			break
		}
		if rel.Relationship == nil || rel.Relationship.Resource == nil || rel.Relationship.Subject == nil || rel.Relationship.Subject.Object == nil {
			continue
		}
		childID := rel.Relationship.Resource.ObjectId
		parentID := rel.Relationship.Subject.Object.ObjectId
		parentMap[childID] = parentID
	}

	// Step 3: Build raw items
	for _, id := range resourceIDs {
		rawItems = append(rawItems, item{
			id:     id,
			parent: parentMap[id],
		})
	}

	// Step 4: Build hierarchical tree
	nodesMap := make(map[string]*Node)
	for _, r := range rawItems {
		nodesMap[r.id] = &Node{
			ID:   r.id,
			Type: resourceType,
		}
	}
	fmt.Println(nodesMap)

	var roots []*Node
	for _, r := range rawItems {
		node := nodesMap[r.id]
		if r.parent == "" {
			roots = append(roots, node)
		} else {
			parentNode, ok := nodesMap[r.parent]
			if ok {
				parentNode.Children = append(parentNode.Children, node)
			} else {
				roots = append(roots, node)
			}
		}
	}

	return roots
}

// ListResourceSubtree returns a hierarchical subtree starting from a specific resource
// func printTree(node *Node, level int) {
// 	if node == nil {
// 		return
// 	}
// 	fmt.Printf("%s%s:%s\n", strings.Repeat(" ", level*2), node.Type, node.ID)
// 	for _, child := range node.Children {
// 		printTree(child, level+1)
// 	}
// }

// ListResourceSubtree builds and returns a hierarchical subtree of targetType (feature only)
func ListResourceSubtree(rootType, rootID, permission, subjectType, subjectID, targetType string) *Node {
	ctx := context.Background()
	rootKey := fmt.Sprintf("%s:%s", rootType, rootID)

	// 1. Accessible resources
	accessible := map[string]bool{}
	if subjectType != "" && subjectID != "" && targetType != "" {
		fmt.Println("[DEBUG] Running LookupResources for", targetType)
		resp, err := Client.LookupResources(ctx, &v1.LookupResourcesRequest{
			ResourceObjectType: targetType,
			Permission:         permission,
			Subject: &v1.SubjectReference{
				Object: &v1.ObjectReference{
					ObjectType: subjectType,
					ObjectId:   subjectID,
				},
			},
		})
		if err != nil {
			log.Printf("lookup failed: %v", err)
		} else {
			for {
				r, err := resp.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Printf("lookup recv error: %v", err)
					break
				}
				key := fmt.Sprintf("%s:%s", targetType, r.ResourceObjectId)
				accessible[key] = true
				fmt.Println("[DEBUG] Accessible resource:", key)
			}
		}
	}

	// 2. Parent relationships
	parentMap := make(map[string]string)
	parentResp, err := Client.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{OptionalRelation: "parent"},
	})
	if err != nil {
		log.Printf("read rel error: %v", err)
		return nil
	}
	for {
		rel, err := parentResp.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("recv rel error: %v", err)
			break
		}
		if rel.Relationship == nil || rel.Relationship.Resource == nil || rel.Relationship.Subject == nil {
			continue
		}
		childKey := fmt.Sprintf("%s:%s", rel.Relationship.Resource.ObjectType, rel.Relationship.Resource.ObjectId)
		parentKey := fmt.Sprintf("%s:%s", rel.Relationship.Subject.Object.ObjectType, rel.Relationship.Subject.Object.ObjectId)
		parentMap[childKey] = parentKey
		fmt.Printf("[DEBUG] ParentRel: %s -> %s\n", childKey, parentKey)
	}

	// 3. Keep nodes only if path reaches root
	nodesMap := make(map[string]*Node)
	keepNodes := map[string]bool{}

	var walkUp func(string) bool
	walkUp = func(node string) bool {
		if node == rootKey {
			keepNodes[node] = true
			return true
		}
		parent, ok := parentMap[node]
		if !ok {
			return false
		}
		if walkUp(parent) {
			keepNodes[node] = true
			keepNodes[parent] = true
			return true
		}
		return false
	}

	for key := range accessible {
		if walkUp(key) {
			fmt.Println("[DEBUG] Path kept:", key, "→ root")
		} else {
			fmt.Println("[DEBUG] Path discarded (not under root):", key)
		}
	}

	// 4. Build feature-only nodes
	for key := range keepNodes {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != targetType {
			continue // skip non-feature types
		}
		if _, ok := nodesMap[key]; !ok {
			nodesMap[key] = &Node{Type: parts[0], ID: parts[1]}
			fmt.Println("[DEBUG] Node created:", key)
		}
	}

	// 5. Build parent-child links only for feature nodes
	for child, parent := range parentMap {
		if _, ok := nodesMap[child]; !ok {
			continue
		}
		if _, ok := nodesMap[parent]; !ok {
			continue
		}
		nodesMap[parent].Children = append(nodesMap[parent].Children, nodesMap[child])
		fmt.Printf("[DEBUG] Linked %s -> %s\n", parent, child)
	}

	// 6. Collect root-level feature nodes (no feature-type parent)
	var roots []*Node
	for key, n := range nodesMap {
		parentKey, hasParent := parentMap[key]
		if !hasParent || nodesMap[parentKey] == nil {
			roots = append(roots, n)
		}
	}

	// 7. Return single root node if only one, else dummy root
	if len(roots) == 1 {
		return roots[0]
	}
	return &Node{Type: targetType, ID: "root", Children: roots}
}
