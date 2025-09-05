package authz

import (
	"context"
	"fmt"
	"io"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

func GetEffectiveSubjects(resourceType, resourceID, permission, subjectType string) ([]string, error) {
	ctx := context.Background()

	resp, err := Client.LookupSubjects(ctx, &v1.LookupSubjectsRequest{
		Resource: &v1.ObjectReference{
			ObjectType: resourceType,
			ObjectId:   resourceID,
		},
		Permission:        permission,
		SubjectObjectType: subjectType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to lookup subjects: %w", err)
	}

	var subjects []string
	for {
		sub, err := resp.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("recv failed: %w", err)
		}
		if sub.Subject != nil {
			subjects = append(subjects, sub.Subject.SubjectObjectId)
		}
	}
	return subjects, nil
}
