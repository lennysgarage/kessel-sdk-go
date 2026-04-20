package main

import (
	"context"
	"fmt"
	"log"
	"os"

	_ "github.com/joho/godotenv/autoload"
	"github.com/project-kessel/kessel-sdk-go/kessel/auth"
	kesselgrpc "github.com/project-kessel/kessel-sdk-go/kessel/grpc"
	v1beta2 "github.com/project-kessel/kessel-sdk-go/kessel/inventory/v1beta2"
	v2 "github.com/project-kessel/kessel-sdk-go/kessel/rbac/v2"
)

func listWorkspaces() {
	ctx := context.Background()

	discovered, err := auth.FetchOIDCDiscovery(ctx, os.Getenv("AUTH_DISCOVERY_ISSUER_URL"), auth.FetchOIDCDiscoveryOptions{
		HttpClient: nil, // Optionally specify an http client - defaults to http.DefaultClient
	})
	if err != nil {
		panic(err)
	}

	oauthCredentials := auth.NewOAuth2ClientCredentials(os.Getenv("AUTH_CLIENT_ID"), os.Getenv("AUTH_CLIENT_SECRET"), discovered.TokenEndpoint)

	inventoryClient, conn, err := v1beta2.NewClientBuilder(os.Getenv("KESSEL_ENDPOINT")).
		Authenticated(kesselgrpc.OAuth2CallCredentials(&oauthCredentials), nil).
		Build()
	if err != nil {
		log.Fatal("Failed to create gRPC client:", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("Failed to close gRPC client: %v", closeErr)
		}
	}()

	// Iterate one-by-one (lazy, constant memory)
	fmt.Println("Listing workspaces:")
	for resp, err := range v2.ListWorkspaces(ctx, inventoryClient, v2.PrincipalSubject("alice", "redhat"), "view_document", "") {
		if err != nil {
			log.Fatalf("Error listing workspaces: %v", err)
		}
		log.Printf("Response: %v", resp)
		log.Printf("Continuation token: %v", resp.Pagination.GetContinuationToken())
	}

	// Materialise all workspaces into a slice
	fmt.Println("\nCollecting all workspaces into a slice:")
	var allWorkspaces []*v1beta2.StreamedListObjectsResponse
	for resp, err := range v2.ListWorkspaces(ctx, inventoryClient, v2.PrincipalSubject("alice", "redhat"), "view_document", "") {
		if err != nil {
			log.Fatalf("Error listing workspaces: %v", err)
		}
		allWorkspaces = append(allWorkspaces, resp)
	}
	fmt.Printf("Total workspaces: %d\n", len(allWorkspaces))
}

func main() {
	listWorkspaces()
}
