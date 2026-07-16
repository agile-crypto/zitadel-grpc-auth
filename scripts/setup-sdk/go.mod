// scripts/setup-sdk is a thin orchestrator over the parent module's
// `admin` package. It is kept as a separate Go module so the script-only
// dependency on github.com/joho/godotenv does not bleed into the public
// zitadel-grpc-auth module.
//
// The parent module (which already pulls in the Zitadel Go SDK via its
// own admin package) is wired in through a relative `replace` directive
// — there is no expectation of pulling zitadel-grpc-auth from a registry
// just to run the bootstrap helper.
module github.com/agile-crypto/zitadel-grpc-auth/scripts/setup-sdk

go 1.25.0

require (
	github.com/joho/godotenv v1.5.1
	github.com/agile-crypto/zitadel-grpc-auth v0.0.0-00010101000000-000000000000
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/zitadel/logging v0.7.0 // indirect
	github.com/zitadel/oidc/v3 v3.45.5 // indirect
	github.com/zitadel/schema v1.3.2 // indirect
	github.com/zitadel/zitadel-go/v3 v3.29.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.40.0 // indirect
	go.opentelemetry.io/otel/metric v1.40.0 // indirect
	go.opentelemetry.io/otel/trace v1.40.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260209200024-4cfbd4190f57 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260209200024-4cfbd4190f57 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// replace github.ibm.com/citius/zitadel-grpc-auth => ../..
