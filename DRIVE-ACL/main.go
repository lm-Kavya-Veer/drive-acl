package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/lm-Kavya-Veer/drive-acl/DRIVE-ACL/authz"
)

type SubjectsResponse struct {
	Subjects []string `json:"subjects"`
	Error    string   `json:"error,omitempty"`
}

// inside authz/handlers.go
func DirectSubjectsHandlerGin(c *gin.Context) {
	resourceType := c.Query("resourceType")
	resourceID := c.Query("resourceId")
	relation := c.Query("relation")
	subjectType := c.Query("subjectType")

	subjects, err := authz.GetDirectSubjects(resourceType, resourceID, relation, subjectType)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"subjects": subjects})
}

func EffectiveSubjectsHandlerGin(c *gin.Context) {
	resourceType := c.Query("resourceType")
	resourceID := c.Query("resourceId")
	permission := c.Query("permission")
	subjectType := c.Query("subjectType")

	subjects, err := authz.GetEffectiveSubjects(resourceType, resourceID, permission, subjectType)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"subjects": subjects})
}

func main() {
	// init SpiceDB client
	authz.InitClient("localhost:50051", "devkey")

	r := gin.Default()

	// r.POST("/assign", func(c *gin.Context) {
	// 	var body struct {
	// 		User       string `json:"user"`
	// 		ObjectID   string `json:"object_id"`
	// 		ObjectType string `json:"object_type"`
	// 		Relation   string `json:"relation"`
	// 	}
	// 	if err := c.ShouldBindJSON(&body); err != nil {
	// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	// 		return
	// 	}
	// 	authz.Assign(body.User, body.ObjectType, body.ObjectID, body.Relation)
	// 	c.JSON(200, gin.H{"status": "assigned"})
	// })

	r.POST("/check", func(c *gin.Context) {
		var body struct {
			User       string `json:"user"`
			ObjectID   string `json:"object_id"`
			ObjectType string `json:"object_type"`
			Permission string `json:"permission"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		allowed := authz.Check(body.User, body.ObjectType, body.ObjectID, body.Permission)
		c.JSON(200, gin.H{"allowed": allowed})
	})

	r.GET("/lookup/:resourceType/:permission/:subjectType/:subjectID", func(c *gin.Context) {
		resourceType := c.Param("resourceType")
		permission := c.Param("permission")
		subjectType := c.Param("subjectType")
		subjectID := c.Param("subjectID")

		hierarchy := authz.ListResourceHierarchy(resourceType, permission, subjectType, subjectID)
		c.JSON(200, gin.H{
			"subject":    map[string]string{"type": subjectType, "id": subjectID},
			"resource":   resourceType,
			"permission": permission,
			"tree":       hierarchy,
		})
	})

	r.POST("/init", func(c *gin.Context) {
		var body map[string]interface{}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		rels := authz.Translate(body)
		authz.LoadRelationships(rels)
		c.JSON(200, gin.H{"loaded": rels})
	})

	// Add new JSON data into SpiceDB
	r.POST("/add", func(c *gin.Context) {
		var body map[string]interface{}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		rels := authz.Translate(body)
		authz.LoadRelationships(rels)
		c.JSON(200, gin.H{"added": rels})
	})

	r.GET("/subtree/:rootType/:rootID/:permission", func(c *gin.Context) {
		rootType := c.Param("rootType")
		rootID := c.Param("rootID")
		permission := c.Param("permission")
		subjectType := c.Query("subjectType") // optional
		subjectID := c.Query("subjectID")     // optional
		targetType := c.Query("targetType")   // optional

		tree := authz.ListResourceSubtree(rootType, rootID, permission, subjectType, subjectID, targetType)
		c.JSON(200, gin.H{
			"root":       fmt.Sprintf("%s:%s", rootType, rootID),
			"permission": permission,
			"subject":    map[string]string{"type": subjectType, "id": subjectID},
			"targetType": targetType,
			"tree":       tree,
		})
	})

	r.GET("/authz/token/:ssoUserId", func(c *gin.Context) {

		ssoUserIdStr := c.Param("ssoUserId")
		ssoUserId, err := strconv.ParseInt(ssoUserIdStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ssoUserId"})
			return
		}

		var partnerID *int64
		if pidStr := c.Query("partnerID"); pidStr != "" {
			pid, err := strconv.ParseInt(pidStr, 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid partnerID"})
				return
			}
			partnerID = &pid
		}

		token, err := authz.GetAuthorizationTokenDataForSSOUserId(ssoUserId, partnerID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, token)
	})

	r.GET("/authz/direct-subjects", DirectSubjectsHandlerGin)
	r.GET("/authz/effective-subjects", EffectiveSubjectsHandlerGin)

	r.Run(":8082")
}
