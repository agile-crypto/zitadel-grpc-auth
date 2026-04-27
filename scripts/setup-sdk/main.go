// setup-sdk provisions a fresh Zitadel instance for the zitadel-grpc-auth
// integration tests and the examples/greeter demo. It is invoked by
// ../bootstrap-zitadel.sh after `docker compose up` has produced the
// first-instance admin PAT.
//
// What it creates (idempotent against a fresh instance only — it expects to
// run once against an empty Zitadel; for re-runs use `bootstrap-zitadel.sh
// reset`):
//
//   - Project           : "greeter-api" (with role assertion enabled so
//     the access token / introspection response carries
//     `urn:zitadel:iam:org:project:roles`)
//   - Roles             : "greeter:user", "greeter:admin"
//   - API application   : "greeter-server" with BASIC auth — its
//     client_id/secret are what the example server uses
//     to call /oauth/v2/introspect (server.Config.IntrospectionClient*)
//   - Service users     : alice (user), root (user+admin), bob (no roles)
//     each with a generated machine secret usable for
//     OAuth2 client_credentials (client.Config.ClientID/Secret)
//   - Action            : "injectGreeterClaims" — copies the user's
//     `greeter:*` project-role grants into a flat string array under the
//     custom claim "urn:greeter:roles" that the example's admin policy
//     checks. Wired to the "Pre Userinfo creation" trigger.
//
// All identifiers and the resulting JSON config are written to
// scripts/generated-config.json. The bootstrap script then slices that
// file into scripts/zitadel-test.env.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	authzV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/authorization/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	orgV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/org/v2"
	projV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Config is the JSON document written to scripts/generated-config.json.
// The bootstrap shell script consumes it via jq.
type Config struct {
	ProjectID string                `json:"project_id"`
	APIApp    AppCredentials        `json:"api_app"`
	Users     map[string]UserConfig `json:"users"`
	ActionID  string                `json:"action_id"`
}

type AppCredentials struct {
	AppID        string `json:"app_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type UserConfig struct {
	UserID       string   `json:"user_id"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Roles        []string `json:"roles"`
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

	var opts []zitadel.Option
	if insecure {
		opts = append(opts, zitadel.WithInsecure(port))
	} else {
		opts = append(opts, zitadel.WithPort(mustParsePort(port)))
	}

	api, err := client.New(ctx, zitadel.New(domain, opts...), client.WithAuth(client.PAT(pat)))
	if err != nil {
		log.Fatalf("Failed to create SDK client: %v", err)
	}
	defer api.Close()

	projSvc := api.ProjectServiceV2()
	userSvc := api.UserServiceV2()
	appSvc := api.ApplicationServiceV2()
	authzSvc := api.AuthorizationServiceV2()
	orgSvc := api.OrganizationServiceV2()
	mgmt := api.ManagementService() // Actions are still on the legacy mgmt service.

	log.Printf("Zitadel: %s:%s (insecure=%v)\n", domain, port, insecure)

	// Resolve the default organization. The PAT belongs to the
	// first-instance machine user which lives in the bootstrap org — we
	// just take the first org the SDK lists. The v2 services need this
	// explicitly on every Create* call.
	orgListResp, err := orgSvc.ListOrganizations(ctx, &orgV2.ListOrganizationsRequest{})
	if err != nil {
		log.Fatalf("ListOrganizations: %v", err)
	}
	if len(orgListResp.GetResult()) == 0 {
		log.Fatal("ListOrganizations: no organizations returned (instance not initialised?)")
	}
	orgID := orgListResp.GetResult()[0].GetId()
	log.Printf("  Default org: %s (%s)\n", orgListResp.GetResult()[0].GetName(), orgID)

	// Step 1: project
	log.Println("=== Step 1: Creating project 'greeter-api' ===")
	projResp, err := projSvc.CreateProject(ctx, &projV2.CreateProjectRequest{
		OrganizationId:       orgID,
		Name:                 "greeter-api",
		ProjectRoleAssertion: true, // ensure roles flow into the token/introspection
	})
	if err != nil {
		log.Fatalf("CreateProject: %v", err)
	}
	projectID := projResp.GetProjectId()
	log.Printf("  Project ID: %s\n", projectID)

	// Step 2: roles
	log.Println("=== Step 2: Creating greeter roles ===")
	roleSpecs := []struct{ Key, DisplayName string }{
		{"greeter:user", "Greeter user (Hello)"},
		{"greeter:admin", "Greeter admin (Admin RPC)"},
	}
	for _, r := range roleSpecs {
		if _, err := projSvc.AddProjectRole(ctx, &projV2.AddProjectRoleRequest{
			ProjectId:   projectID,
			RoleKey:     r.Key,
			DisplayName: r.DisplayName,
		}); err != nil {
			log.Fatalf("AddProjectRole(%s): %v", r.Key, err)
		}
	}
	log.Printf("  %d roles created\n", len(roleSpecs))

	// Step 3: API application (introspection credentials)
	log.Println("=== Step 3: Creating API application 'greeter-server' ===")
	appResp, err := appSvc.CreateApplication(ctx, &appV2.CreateApplicationRequest{
		ProjectId: projectID,
		Name:      "greeter-server",
		ApplicationType: &appV2.CreateApplicationRequest_ApiConfiguration{
			ApiConfiguration: &appV2.CreateAPIApplicationRequest{
				AuthMethodType: appV2.APIAuthMethodType_API_AUTH_METHOD_TYPE_BASIC,
			},
		},
	})
	if err != nil {
		log.Fatalf("CreateApplication: %v", err)
	}
	apiCfg := appResp.GetApiConfiguration()
	apiApp := AppCredentials{
		AppID:        appResp.GetApplicationId(),
		ClientID:     apiCfg.GetClientId(),
		ClientSecret: apiCfg.GetClientSecret(),
	}
	log.Printf("  App ID: %s  Client ID: %s\n", apiApp.AppID, apiApp.ClientID)

	// Step 4: service users
	log.Println("=== Step 4: Creating service users ===")
	type userSpec struct {
		username, displayName string
		roles                 []string
	}
	specs := []userSpec{
		{"alice", "Alice (greeter:user)", []string{"greeter:user"}},
		{"root", "Root (greeter:user + greeter:admin)", []string{"greeter:user", "greeter:admin"}},
		{"bob", "Bob (no greeter roles)", nil},
	}

	userConfigs := make(map[string]UserConfig, len(specs))
	for _, s := range specs {
		log.Printf("  Creating user: %s", s.username)
		desc := fmt.Sprintf("zitadel-grpc-auth test user: %s", s.displayName)
		userResp, err := userSvc.CreateUser(ctx, &userV2.CreateUserRequest{
			OrganizationId: orgID,
			Username:       strPtr(s.username),
			UserType: &userV2.CreateUserRequest_Machine_{
				Machine: &userV2.CreateUserRequest_Machine{
					Name:            s.displayName,
					Description:     &desc,
					AccessTokenType: userV2.AccessTokenType_ACCESS_TOKEN_TYPE_BEARER,
				},
			},
		})
		if err != nil {
			log.Fatalf("CreateUser(%s): %v", s.username, err)
		}
		userID := userResp.GetId()

		secretResp, err := userSvc.AddSecret(ctx, &userV2.AddSecretRequest{UserId: userID})
		if err != nil {
			log.Fatalf("AddSecret(%s): %v", s.username, err)
		}

		getUserResp, err := userSvc.GetUserByID(ctx, &userV2.GetUserByIDRequest{UserId: userID})
		if err != nil {
			log.Fatalf("GetUserByID(%s): %v", s.username, err)
		}
		clientID := getUserResp.GetUser().GetPreferredLoginName()

		if len(s.roles) > 0 {
			if _, err := authzSvc.CreateAuthorization(ctx, &authzV2.CreateAuthorizationRequest{
				OrganizationId: orgID,
				UserId:         userID,
				ProjectId:      projectID,
				RoleKeys:       s.roles,
			}); err != nil {
				log.Fatalf("CreateAuthorization(%s): %v", s.username, err)
			}
			log.Printf("    Roles: %s", strings.Join(s.roles, ", "))
		}

		userConfigs[s.username] = UserConfig{
			UserID:       userID,
			ClientID:     clientID,
			ClientSecret: secretResp.GetClientSecret(),
			Roles:        s.roles,
		}
		log.Printf("    client_id=%s\n", clientID)
	}

	// Step 5: pre-userinfo action
	//
	// The action walks ctx.v1.user.grants, picks every role key starting
	// with "greeter:", and emits them as a deduplicated string array under
	// the custom claim "urn:greeter:roles". The example greeter server's
	// admin policy reads exactly that claim via
	// claims.HasStringInSlice("urn:greeter:roles", "greeter:admin").
	log.Println("=== Step 5: Creating action 'injectGreeterClaims' ===")
	script := `function injectGreeterClaims(ctx, api) {
  var roles = [];
  try {
    var grants = ctx.v1.user.grants;
    if (grants && grants.count > 0 && grants.grants) {
      for (var i = 0; i < grants.grants.length; i++) {
        var g = grants.grants[i];
        if (!g.roles) continue;
        for (var j = 0; j < g.roles.length; j++) {
          var r = g.roles[j];
          if (r.indexOf('greeter:') !== 0) continue;
          var seen = false;
          for (var k = 0; k < roles.length; k++) {
            if (roles[k] === r) { seen = true; break; }
          }
          if (!seen) roles.push(r);
        }
      }
    }
  } catch (e) {}
  api.v1.claims.setClaim('urn:greeter:roles', roles);
}`
	actionResp, err := mgmt.CreateAction(ctx, &management.CreateActionRequest{
		Name:          "injectGreeterClaims",
		Script:        script,
		Timeout:       durationpb.New(10 * time.Second),
		AllowedToFail: false,
	})
	if err != nil {
		log.Fatalf("CreateAction: %v", err)
	}
	actionID := actionResp.GetId()
	log.Printf("  Action ID: %s\n", actionID)

	// Step 6: wire flow trigger
	// FlowType "2"  = customise token / userinfo
	// TriggerType "4" = pre userinfo creation (also covers introspection)
	log.Println("=== Step 6: Wiring flow trigger (Pre Userinfo creation) ===")
	if _, err := mgmt.SetTriggerActions(ctx, &management.SetTriggerActionsRequest{
		FlowType:    "2",
		TriggerType: "4",
		ActionIds:   []string{actionID},
	}); err != nil {
		log.Fatalf("SetTriggerActions: %v", err)
	}
	log.Println("  Done")

	// Step 7: Persist generated-config.json next to the script
	cfg := Config{
		ProjectID: projectID,
		APIApp:    apiApp,
		Users:     userConfigs,
		ActionID:  actionID,
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

func strPtr(s string) *string { return &s }

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustParsePort(s string) uint16 {
	var p uint16
	fmt.Sscanf(s, "%d", &p)
	if p == 0 {
		p = 443
	}
	return p
}
