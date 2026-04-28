# Greeter — example client + server

A minimal end-to-end example showing how to wire `zitadel-grpc-auth` into a
real gRPC service with three representative RPCs:

| RPC       | Auth requirement                                       |
| --------- | ------------------------------------------------------ |
| `Healthz` | Public — bypasses auth via `Config.PublicMethods`      |
| `Hello`   | Authenticated only — registered with an empty policy slice |
| `Admin`   | Authenticated **and** `urn:greeter:permissions` contains `greeter:admin` |

## Layout

```
examples/greeter/
├── proto/greeter.proto         service definition
├── pb/                         generated Go bindings (committed for convenience)
├── server/main.go              runnable example server
├── client/main.go              runnable example client
└── e2e_test.go                 in-process integration test (no Zitadel needed)
```

## Run with auth disabled (no Zitadel needed)

Two terminals:

```bash
# terminal 1
go run ./examples/greeter/server

# terminal 2
go run ./examples/greeter/client -op healthz
go run ./examples/greeter/client -op hello -name alice
go run ./examples/greeter/client -op admin -name "rotate keys"
```

In disabled mode every RPC succeeds; the `Hello` response shows an empty
`subject` (no claims in handler context).

## Run with auth enabled against a real Zitadel

The server needs API-app credentials to call `/oauth/v2/introspect`; the
client needs service-user credentials to acquire a token via
`client_credentials`:

```bash
# terminal 1 — server
AUTH_ENABLED=true \
ZITADEL_ISSUER=http://localhost:8080 \
INTROSPECT_ID=<api-app-client-id> \
INTROSPECT_SECRET=<api-app-client-secret> \
  go run ./examples/greeter/server

# terminal 2 — client
AUTH_ENABLED=true \
ZITADEL_ISSUER=http://localhost:8080 \
CLIENT_ID=<service-user-client-id> \
CLIENT_SECRET=<service-user-client-secret> \
PROJECT_ID=<zitadel-project-id> \
  go run ./examples/greeter/client -op hello -name alice
```

For the `admin` RPC to succeed, the service user's introspection response
must include a custom claim `urn:greeter:permissions` that contains the
string `greeter:admin`. The simplest way to set that up end-to-end is the
bootstrap helper in [`scripts/`](../../scripts/README.md), which uses the
[`admin`](../../admin) package to provision the project, roles, API app,
service users, and the Pre-Userinfo action that flattens role grants into
the `urn:greeter:permissions` claim.

## Regenerating the protobuf bindings

```bash
cd examples/greeter
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       -I proto proto/greeter.proto
mv greeter.pb.go greeter_grpc.pb.go pb/
```
