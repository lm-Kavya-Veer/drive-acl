package authz

import (
	"log"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

func Assign(user, objectType, objectID, relation string) {
	_, err := Client.WriteRelationships(Context(), &v1.WriteRelationshipsRequest{
		Updates: []*v1.RelationshipUpdate{
			{
				Operation: v1.RelationshipUpdate_OPERATION_CREATE,
				Relationship: &v1.Relationship{
					Resource: &v1.ObjectReference{
						ObjectType: objectType,
						ObjectId:   objectID,
					},
					Relation: relation,
					Subject: &v1.SubjectReference{
						Object: &v1.ObjectReference{
							ObjectType: "user",
							ObjectId:   user,
						},
					},
				},
			},
		},
	})
	if err != nil {
		log.Printf("failed to assign: %v", err)
	}
}

//extra
