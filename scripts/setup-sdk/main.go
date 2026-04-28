// setup-sdk provisions a fresh Zitadel instance for the zitadel-grpc-auth
// integration tests and the examples/greeter demo. It is invoked by
// ../bootstrap-zitadel.sh after `docker compose up` has produced the
// first-instance admin PAT.
//
// What it creates (idempotent — safe to re-run):
//
//   - Project           : "greeter-api" (with role assertion enabled so
//     the access token / introspection response carries
//     `urn:zitadel:iam:org:project:roles`)
//   - Roles             : "greeter:user", "greeter:admin"
//   - API application   : "greeter-api-server" with BASIC auth — its
//     client_id/secret are what the example server uses
//     to call /oauth/v2/introspect (server.Config.IntrospectionClient*)
//   - Service users     : alice (user), root (user+admin), bob (no roles)
//     each with a generated machine secret usable for
//     OAuth2 client_credentials (client.Config.ClientID/Secret)
//   - Action            : auto-named "injectUrnGreeterClaims" — copies the
//     user's project-role grants into a flat string array under the
//     custom claim "urn:greeter:permissions" that the example's admin
//     policy checks. Also wires the (currently unused) key/policy access
//     metadata blobs into matching claims, in case operators want to
//     experiment with the resource-scoping helpers. Wired to the
//     "Pre Userinfo creation" trigger.
//
// All identifiers and the resulting JSON config are written to
// scripts/generated-config.json. The bootstrap script then slices that
// file into scripts/zitadel-test.env.
//
// This binary is a thin orchestrator over the parent module's `admin`
// package. All Zitadel-API specifics (idempotency, action wiring without
// clobbering, role reconciliation) live there.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	"github.ibm.com/citius/zitadel-grpc-auth/admin"
)

// Config is the JSON document written to scripts/generated-config.json.
// The bootstrap shell script consumes it via jq.
//
// The shape is preserved for backwards compatibility with the existing
// emit_test_env step in bootstrap-zitadel.sh, which reads
// `.api_app.client_id`, `.api_app.client_secret`, `.project_id`, and the
// per-user `.users[*].client_id` / `.client_secret` entries.
type Config struct {
	ProjectID string                `json:"project_id"`
	APIApp    AppCredentials        `json:"api_app"`
	Users     map[string]UserConfig `json:"users"`
	ActionID  string                `json:"action_id"`
}

type AppCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type UserConfig struct {
	UserID       string   `json:"user_id"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Roles        []string `json:"roles"`
}

// userSpec is the local catalogue of greeter test users.
type userSpec struct {
	username    string
	displayName string
	roles       []string
}

func main() {
	// .env is written next to the binary by bootstrap-zitadel.sh.
	if err := godotenv.Load(filepath.Join("..", ".env")); err != nil {
		_ = godotenv.Load(".env")
	}

	pat := os.Getenv("ZITADEL_ADMIN_PAT")
	if pat == "" {
		log.Fatal("ZITADEL_ADMIN_PAT is required. Set it in .env or export it.")
	}

	domain := envOrDefault("ZITADEL_DOMAIN", "localhost")
	port := envOrDefault("ZITADEL_PORT", "8080")
	insecure := os.Getenv("ZITADEL_INSECURE") == "true"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	log.Printf("Zitadel: %s:%s (insecure=%v)\n", domain, port, insecure)

	// Bootstrap the project, roles, API app, and action. The
	// admin client at this stage doesn't need ProjectID — Bootstrap
	// creates the project itself.
	bootstrapAdm, err := admin.NewClient(ctx, admin.Config{
		Domain:    domain,
		Port:      port,
		Insecure:  insecure,
		PAT:       pat,
		Namespace: "urn:greeter",
	})
	if err != nil {
		log.Fatalf("admin.NewClient (bootstrap): %v", err)
	}
	defer bootstrapAdm.Close()

	log.Println(" Bootstrap project, roles, API app, action ")
	bootstrap, err := bootstrapAdm.Bootstrap(ctx, admin.BootstrapInput{
		ProjectName:    "greeter-api",
		ClaimNamespace: "urn:greeter",
		Operations: []admin.Operation{
			{Method: "/greeter.v1.Greeter/Hello", Permission: "greeter:user", DisplayName: "Greeter user (Hello)"},
			{Method: "/greeter.v1.Greeter/Admin", Permission: "greeter:admin", DisplayName: "Greeter admin (Admin RPC)"},
		},
	})
	if err != nil {
		log.Fatalf("admin.Bootstrap: %v", err)
	}
	log.Printf("  Project ID:        %s", bootstrap.ProjectID)
	log.Printf("  Action ID:         %s", bootstrap.ActionID)
	log.Printf("  API app client ID: %s", bootstrap.APIApp.ClientID)
	if bootstrap.APIApp.ClientSecret == "" {
		log.Println("  API app client secret already provisioned — empty in result by design")
		log.Println("  (re-run after `bootstrap-zitadel.sh reset` if you need it surfaced again)")
	}

	apiApp := AppCredentials{
		ClientID:     bootstrap.APIApp.ClientID,
		ClientSecret: bootstrap.APIApp.ClientSecret,
	}

	// Onboard the test users. We re-create the admin client
	// with the project ID we just learned so onboard's resolveProject
	// is unambiguous even on a multi-project org.
	onboardAdm, err := admin.NewClient(ctx, admin.Config{
		Domain:    domain,
		Port:      port,
		Insecure:  insecure,
		PAT:       pat,
		Namespace: "urn:greeter",
		ProjectID: bootstrap.ProjectID,
	})
	if err != nil {
		log.Fatalf("admin.NewClient (onboard): %v", err)
	}
	defer onboardAdm.Close()

	specs := []userSpec{
		{"alice", "Alice (greeter:user)", []string{"greeter:user"}},
		{"root", "Root (greeter:user + greeter:admin)", []string{"greeter:user", "greeter:admin"}},
		{"bob", "Bob (no greeter roles)", nil},
	}

	log.Println(" Onboard service users ")
	userConfigs := make(map[string]UserConfig, len(specs))
	for _, s := range specs {
		log.Printf("  Onboarding: %s", s.username)
		res, err := onboardAdm.Onboard(ctx, admin.OnboardInput{
			Username:    s.username,
			DisplayName: s.displayName,
			Permissions: s.roles,
		})
		if err != nil {
			log.Fatalf("admin.Onboard(%s): %v", s.username, err)
		}
		if res.ClientSecret == "" {
			// Admin only mints a secret on first creation; re-runs
			// against an existing user can't surface it. The bootstrap
			// shell helper guards against this by wiping volumes on
			// `reset`, but warn loudly if we hit it.
			log.Printf("    WARNING: empty client_secret for existing user %q; run `bootstrap-zitadel.sh reset` for a clean slate", s.username)
		}
		userConfigs[s.username] = UserConfig{
			UserID:       res.UserID,
			ClientID:     res.ClientID,
			ClientSecret: res.ClientSecret,
			Roles:        s.roles,
		}
		log.Printf("    user_id=%s  client_id=%s", res.UserID, res.ClientID)
	}

	// Persist generated-config.json next to the script.
	cfg := Config{
		ProjectID: bootstrap.ProjectID,
		APIApp:    apiApp,
		Users:     userConfigs,
		ActionID:  bootstrap.ActionID,
	}
	configPath := filepath.Join("..", "generated-config.json")
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}

	fmt.Printf("\n========================================\n  Setup complete!\n  Config: %s\n========================================\n\n", configPath)
	fmt.Printf("API Application (introspection):\n  Client ID:     %s\n  Client Secret: %s\n\n", apiApp.ClientID, apiApp.ClientSecret)
	for _, name := range []string{"alice", "root", "bob"} {
		u := userConfigs[name]
		fmt.Printf("User %q:\n  Client ID:     %s\n  Client Secret: %s\n  Roles:         %v\n\n", name, u.ClientID, u.ClientSecret, u.Roles)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
