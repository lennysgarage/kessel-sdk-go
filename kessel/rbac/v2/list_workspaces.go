package v2

import (
	"context"
	"fmt"
	"io"
	"iter"

	v1beta2 "github.com/project-kessel/kessel-sdk-go/kessel/inventory/v1beta2"
)

// ListWorkspaces returns a lazy iterator over all workspaces that the given
// subject has the specified relation to. It wraps the StreamedListObjects gRPC
// call and automatically handles continuation-token pagination across pages.
//
// Iterate one-by-one (lazy, low memory):
//
//	for resp, err := range v2.ListWorkspaces(ctx, client, subject, "viewer", "") {
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    fmt.Println(resp.Object.GetResourceId())
//	}
//
// Materialise into a slice (eager, all results in memory):
//
//	var all []*v1beta2.StreamedListObjectsResponse
//	for resp, err := range v2.ListWorkspaces(ctx, client, subject, "viewer", "") {
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    all = append(all, resp)
//	}
func ListWorkspaces(
	ctx context.Context,
	inventory v1beta2.KesselInventoryServiceClient,
	subject *v1beta2.SubjectReference,
	relation string,
	continuationToken string,
) iter.Seq2[*v1beta2.StreamedListObjectsResponse, error] {
	return func(yield func(*v1beta2.StreamedListObjectsResponse, error) bool) {
		for {
			var pagination *v1beta2.RequestPagination
			if continuationToken != "" {
				pagination = &v1beta2.RequestPagination{
					Limit:             1000,
					ContinuationToken: &continuationToken,
				}
			}

			request := &v1beta2.StreamedListObjectsRequest{
				ObjectType: WorkspaceType(),
				Relation:   relation,
				Subject:    subject,
				Pagination: pagination,
			}

			stream, err := inventory.StreamedListObjects(ctx, request)
			if err != nil {
				yield(nil, fmt.Errorf("failed to start stream: %w", err))
				return
			}

			var lastToken string
			for {
				response, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					yield(nil, fmt.Errorf("error receiving from stream: %w", err))
					return
				}

				// stop fetching if loop broke early
				if !yield(response, nil) {
					return
				}

				if response.Pagination != nil {
					lastToken = response.Pagination.ContinuationToken
				}
			}

			if lastToken == "" {
				break
			}
			continuationToken = lastToken
		}
	}
}
