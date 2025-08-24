package authz

import (
	"log"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

func LoadRelationships(rels []string) {
	var updates []*v1.RelationshipUpdate

	for _, r := range rels {
		// format: "objectType:objectId#relation@subjectType:subjectId"
		parts := strings.Split(r, "#")
		if len(parts) != 2 {
			log.Printf("invalid relation format: %s", r)
			continue
		}
		left, right := parts[0], parts[1]

		// left = "partner:Dentsu"
		objParts := strings.Split(left, ":")
		if len(objParts) != 2 {
			log.Printf("invalid resource format: %s", left)
			continue
		}
		objType, objId := objParts[0], objParts[1]

		// right = "user@users:alice"
		relParts := strings.Split(right, "@")
		if len(relParts) != 2 {
			log.Printf("invalid relation/subject format: %s", right)
			continue
		}
		relation := relParts[0]

		subParts := strings.Split(relParts[1], ":")
		if len(subParts) != 2 {
			log.Printf("invalid subject format: %s", relParts[1])
			continue
		}
		subType, subId := subParts[0], subParts[1]

		update := &v1.RelationshipUpdate{
			Operation: v1.RelationshipUpdate_OPERATION_CREATE,
			Relationship: &v1.Relationship{
				Resource: &v1.ObjectReference{
					ObjectType: objType,
					ObjectId:   objId,
				},
				Relation: relation,
				Subject: &v1.SubjectReference{
					Object: &v1.ObjectReference{
						ObjectType: subType,
						ObjectId:   subId,
					},
				},
			},
		}
		updates = append(updates, update)
	}

	if len(updates) == 0 {
		log.Println("no valid relationships to write")
		return
	}

	_, err := Client.WriteRelationships(Context(), &v1.WriteRelationshipsRequest{
		Updates: updates,
	})
	if err != nil {
		log.Fatalf("failed to write relationships: %v", err)
	}
}
