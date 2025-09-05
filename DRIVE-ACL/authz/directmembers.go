package authz

import (
	"context"
	"fmt"
	"io"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

func GetDirectSubjects(resourceType, resourceID, relation, subjectType string) ([]string, error) {
	ctx := context.Background()

	resp, err := Client.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType:       resourceType,
			OptionalResourceId: resourceID,
			OptionalRelation:   relation,
			OptionalSubjectFilter: &v1.SubjectFilter{
				SubjectType: subjectType,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read relationships: %w", err)
	}

	var subjects []string
	for {
		rel, err := resp.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("recv failed: %w", err)
		}
		if rel.Relationship != nil && rel.Relationship.Subject != nil {
			subjects = append(subjects, rel.Relationship.Subject.Object.ObjectId)
		}
	}
	return subjects, nil
}
