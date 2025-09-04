package authz

import (
	"log"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
)

func Check(user, objectType, objectID, permission string) bool {
	resp, err := Client.CheckPermission(Context(), &v1.CheckPermissionRequest{
		Resource: &v1.ObjectReference{
			ObjectType: objectType,
			ObjectId:   objectID,
		},
		Permission: permission,
		Subject: &v1.SubjectReference{
			Object: &v1.ObjectReference{
				ObjectType: "users1",
				ObjectId:   user,
			},
		},
	})
	if err != nil {
		log.Printf("failed to check: %v", err)
		return false
	}
	return resp.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION
}
