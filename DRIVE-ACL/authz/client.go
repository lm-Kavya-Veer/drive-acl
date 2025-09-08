package authz

import (
	"context"
	"log"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	grpcutil "github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var Client v1.PermissionsServiceClient

func InitClient(addr, secret string) {
	conn, err := grpc.NewClient(
		addr,
		grpcutil.WithInsecureBearerToken(secret),
		grpc.WithTransportCredentials(insecure.NewCredentials()), // Allow insecure connection
		grpc.WithBlock(),
	)
	if err != nil {
		log.Fatalf("failed to dial SpiceDB: %v", err)
	}
	Client = v1.NewPermissionsServiceClient(conn)
}

func Context() context.Context {
	return context.Background()
}
