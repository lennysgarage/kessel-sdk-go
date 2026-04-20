# Kessel SDK for Go

The official Go SDK for the Kessel inventory and authorization service. This SDK provides gRPC client implementation for secure communication.

## Features

- **gRPC client support** - High-performance gRPC communication
- **Type-safe API** - Generated from protobuf definitions
- **Production ready** - Built with security, performance, and reliability in mind

## Installation

```bash
go get github.com/project-kessel/kessel-sdk-go
```

## Quick Start

### gRPC Client

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/project-kessel/kessel-sdk-go/kessel/config"
	v1beta2 "github.com/project-kessel/kessel-sdk-go/kessel/inventory/v1beta2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func main() {
    ctx := context.Background()
    
    grpcConfig := config.NewCompatibilityConfig(
        config.WithGRPCEndpoint("your-kessel-server:9000"),
        config.WithGRPCInsecure(true),
    )

    // Using insecure credentials for local development
    var dialOpts []grpc.DialOption
    dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
    dialOpts = append(dialOpts,
        grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(grpcConfig.MaxReceiveMessageSize)),
        grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(grpcConfig.MaxSendMessageSize)),
    )

    conn, err := grpc.NewClient(grpcConfig.Url, dialOpts...)
    if err != nil {
        log.Fatal("Failed to create gRPC client:", err)
    }
    defer func() {
        if closeErr := conn.Close(); closeErr != nil {
            log.Printf("Failed to close gRPC client: %v", closeErr)
        }
    }()

    inventoryClient := v1beta2.NewKesselInventoryServiceClient(conn)

    // Example request using the external API types
    checkRequest := &v1beta2.CheckRequest{
        Object: &v1beta2.ResourceReference{
            ResourceType: "host",
            ResourceId:   "server-123",
            Reporter: &v1beta2.ReporterReference{
                Type: "HBI",
            },
        },
        Relation: "member",
        Subject: &v1beta2.SubjectReference{
            Resource: &v1beta2.ResourceReference{
                ResourceType: "user",
                ResourceId:   "alice",
            },
        },
    }

    response, err := inventoryClient.Check(ctx, checkRequest)
    if err != nil {
        if st, ok := status.FromError(err); ok {
            switch st.Code() {
            case codes.Unavailable:
                log.Fatal("Service unavailable: ", err)
            case codes.PermissionDenied:
                log.Fatal("Permission denied: ", err)
            default:
                log.Fatal("gRPC connection error: ", err)
            }
        } else {
            log.Fatal("Unknown error: ", err)
        }
    }

    log.Printf("Check result: %v", response.Allowed)
}
```

## Configuration

### gRPC Endpoint

Specify the gRPC endpoint:

```go
grpcConfig := config.NewCompatibilityConfig(
    config.WithGRPCEndpoint("your-kessel-server:9000"),
    config.WithGRPCInsecure(true),
)
```

## Error Handling

The SDK uses standard gRPC status codes:

```go
response, err := inventoryClient.Check(ctx, checkRequest)
if err != nil {
    if st, ok := status.FromError(err); ok {
        switch st.Code() {
        case codes.Unavailable:
            log.Fatal("Service unavailable:", err)
        case codes.PermissionDenied:
            log.Fatal("Permission denied:", err)
        default:
            log.Fatal("gRPC connection error:", err)
        }
    } else {
        log.Fatal("Unknown error:", err)
    }
}
```

## Listing Workspaces

The `ListWorkspaces` helper automatically paginates through all workspaces
a subject can access. Continuation tokens are handled internally.

```go
import v2 "github.com/project-kessel/kessel-sdk-go/kessel/rbac/v2"

// Lazy iteration (constant memory)
for resp, err := range v2.ListWorkspaces(ctx, client, subject, "viewer", "") {
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(resp.Object.GetResourceId())
}

// Materialise into a slice
var all []*v1beta2.StreamedListObjectsResponse
for resp, err := range v2.ListWorkspaces(ctx, client, subject, "viewer", "") {
    if err != nil {
        log.Fatal(err)
    }
    all = append(all, resp)
}
```

See [`examples/rbac/list_workspaces.go`](./examples/rbac/list_workspaces.go) for a complete working example.

## Examples

Complete examples are available in the [`examples/`](./examples/) directory:

- [`examples/grpc/main.go`](./examples/grpc/main.go) - gRPC client usage

To run the examples:

```bash
# Build examples
make build

# Run gRPC example
./bin/grpc-example
```

## Development

### Prerequisites

- Go 1.24 or later
- Docker or Podman (for linting)
- Protocol Buffers compiler (for code generation)

### Building

```bash
# Install dependencies
go mod download

# Run linting
make lint

# Run tests
make test

# Build examples
make build

# Run tests with coverage
make test-coverage
```

### Available Make Targets

| Target | Description |
|--------|-------------|
| `make help` | Display all available targets |

## Release Instructions

This section provides step-by-step instructions for maintainers to release a new version of the Kessel SDK for Go.

### Version Management

This project follows [Semantic Versioning 2.0.0](https://semver.org/). Version numbers use the format `MAJOR.MINOR.PATCH`:

- **MAJOR**: Increment for incompatible API changes
- **MINOR**: Increment for backward-compatible functionality additions
- **PATCH**: Increment for backward-compatible bug fixes

**Note**: SDK versions across different languages (Ruby, Python, Go, etc.) do not need to be synchronized. Each language SDK can evolve independently based on its specific requirements and release schedule.

### Prerequisites for Release

- Write access to the GitHub repository
- Ensure quality checks are passing
- Review and update CHANGELOG or release notes as needed
- Go 1.24 or higher
- [buf](https://github.com/bufbuild/buf) for protobuf/gRPC code generation:
  ```bash
  # On macOS
  brew install bufbuild/buf/buf
  
  # On Linux
  curl -sSL "https://github.com/bufbuild/buf/releases/latest/download/buf-$(uname -s)-$(uname -m)" -o "/usr/local/bin/buf" && chmod +x "/usr/local/bin/buf"
  ```

### Release Process

1. **Determine the version**

Check existing tags (e.g. on GitHub or locally after `git fetch --tags`), choose the next version using semantic versioning (see [Version Management](#version-management) above), then set `VERSION` for the steps below:

```bash
export VERSION=X.Y.Z
echo "Releasing version: v${VERSION}"
```

2. **Update Dependencies (if needed)**

```bash
# Regenerate gRPC code if there are updates to the Kessel Inventory API
make generate
```

3. **Run Quality Checks**

```bash
# Run linting
make lint

# Run tests
make test

# Build examples
make build
```

4. **Commit and push (if needed)**

If `make generate` or other changes produced diffs, commit and push them before tagging:

```bash
git add .
git commit -m "chore: regenerate protobuf code"
git push origin main
```

5. **Tag the Release**

```bash
git tag -a v${VERSION} -m "Release version ${VERSION}"
git push origin v${VERSION}
```

6. **Create GitHub Release**

```bash
gh release create v${VERSION} --title "v${VERSION}" --generate-notes
```

Or manually:

- Go to the [GitHub Releases page](https://github.com/project-kessel/kessel-sdk-go/releases)
- Click "Create a new release"
- Select the tag you just created
- Add release notes describing the changes
- Publish the release

After the tag is published, users can install that version with:

```bash
go get github.com/project-kessel/kessel-sdk-go@v${VERSION}
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
