//go:build integration

package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	projV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	userV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

func TestIntegrationHumanProvisioning(t *testing.T) {
	cfg := integrationAdminConfig(t)
	suffix := integrationSuffix(t)
	projectName := "zga-human-it-" + suffix
	namespace := "urn:zga:it:" + suffix
	webInput := WebApplicationInput{
		Name:                   "zga-human-web-" + suffix,
		RedirectURIs:           []string{"http://127.0.0.1:7861/auth/callback/" + suffix},
		PostLogoutRedirectURIs: []string{"http://127.0.0.1:7861/signed-out/" + suffix},
		EnableRefreshTokens:    true,
		DevMode:                true,
	}
	operations := []Operation{
		{Method: "/integration.Keys/Read", Permission: "keys.read", DisplayName: "Read keys"},
		{Method: "/integration.Keys/Write", Permission: "keys.write", DisplayName: "Write keys"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bootstrapClient, err := NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewClient for bootstrap: %v", err)
	}
	defer bootstrapClient.Close()
	bootstrap, err := bootstrapClient.Bootstrap(ctx, BootstrapInput{
		ProjectName:    projectName,
		ClaimNamespace: namespace,
		Operations:     operations,
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	createdUsers := make([]string, 0, 3)
	defer func() {
		cleanupIntegrationResources(t, bootstrapClient, bootstrap.ProjectID, bootstrap.ActionID, createdUsers)
	}()
	orgID, err := bootstrapClient.resolveOrgID(ctx)
	if err != nil {
		t.Fatalf("resolve integration organization: %v", err)
	}

	cfg.ProjectID = bootstrap.ProjectID
	cfg.Namespace = namespace
	cfg.OrgID = orgID
	client, err := NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewClient for project: %v", err)
	}
	defer client.Close()

	web, err := client.EnsureWebApplication(ctx, webInput)
	if err != nil {
		t.Fatalf("EnsureWebApplication create: %v", err)
	}
	if !web.Created || web.Updated || web.ApplicationID == "" || web.ClientID == "" {
		t.Fatalf("first web application result = %+v, want created public client", web)
	}
	integrationEventually(t, "web application creation", func() (bool, error) {
		application, err := client.lookupApplicationByName(ctx, bootstrap.ProjectID, webInput.Name)
		return application != nil, err
	})
	webAgain, err := client.EnsureWebApplication(ctx, webInput)
	if err != nil {
		t.Fatalf("EnsureWebApplication repeat: %v", err)
	}
	if webAgain.Created || webAgain.Updated || webAgain.ApplicationID != web.ApplicationID || webAgain.ClientID != web.ClientID {
		t.Fatalf("repeated web application result = %+v, want unchanged IDs", webAgain)
	}

	target := HumanConfiguration{
		Username:               "zga-human-" + suffix,
		GivenName:              "Integration",
		FamilyName:             "Target",
		DisplayName:            "Integration Target " + suffix,
		Email:                  "zga-human+" + suffix + "@example.com",
		EmailVerified:          true,
		PasswordChangeRequired: true,
		Permissions:            []string{"keys.read"},
		KeyAccess: KeyAccess{
			AllowedKeyPatterns: []string{"integration-" + suffix + "-*"},
			DenyKeyPatterns:    []string{"integration-" + suffix + "-blocked-*"},
		},
		PolicyAccess: PolicyAccess{AllowedPolicyPatterns: []string{"policy-" + suffix + "-*"}},
	}
	sentinel := HumanConfiguration{
		Username:      "zga-sentinel-" + suffix,
		GivenName:     "Integration",
		FamilyName:    "Sentinel",
		DisplayName:   "Integration Sentinel " + suffix,
		Email:         "zga-sentinel+" + suffix + "@example.com",
		EmailVerified: true,
		Permissions:   []string{"keys.write"},
		KeyAccess:     KeyAccess{AllowedKeyPatterns: []string{"sentinel-" + suffix + "-*"}},
	}
	createdUsers = append(createdUsers, target.Username, sentinel.Username)
	targetPassword := "A9!First-" + suffix + "-Password"
	targetResult, err := client.OnboardHuman(ctx, humanOnboardInput(target, targetPassword))
	if err != nil {
		t.Fatalf("OnboardHuman target create: %v", err)
	}
	if !targetResult.Created || targetResult.UserID == "" || targetResult.LoginName == "" {
		t.Fatalf("first human result = %+v, want created user", targetResult)
	}
	integrationEventually(t, "target user creation", func() (bool, error) {
		user, err := client.lookupUserByUsername(ctx, cfg.OrgID, target.Username)
		return user != nil, err
	})
	targetBeforeRepeat := integrationPasswordChanged(t, ctx, client, targetResult.UserID)
	time.Sleep(10 * time.Millisecond)
	repeatedInput := humanOnboardInput(target, "B8!Ignored-"+suffix+"-Password")
	targetAgain, err := client.OnboardHuman(ctx, repeatedInput)
	if err != nil {
		t.Fatalf("OnboardHuman target repeat: %v", err)
	}
	if targetAgain.Created || targetAgain.UserID != targetResult.UserID {
		t.Fatalf("repeated human result = %+v, want reused user %s", targetAgain, targetResult.UserID)
	}
	targetAfterRepeat := integrationPasswordChanged(t, ctx, client, targetResult.UserID)
	if !targetAfterRepeat.Equal(targetBeforeRepeat) {
		t.Fatalf("repeated onboarding changed password timestamp: before=%s after=%s", targetBeforeRepeat, targetAfterRepeat)
	}

	sentinelResult, err := client.OnboardHuman(ctx, humanOnboardInput(sentinel, "C7!Sentinel-"+suffix+"-Password"))
	if err != nil {
		t.Fatalf("OnboardHuman sentinel: %v", err)
	}
	if !sentinelResult.Created {
		t.Fatalf("sentinel result = %+v, want created user", sentinelResult)
	}

	expected := HumanAuthConfigurationInput{
		ClaimNamespace: namespace,
		Humans:         []HumanConfiguration{target, sentinel},
		WebApplication: webInput,
	}
	integrationAwaitVerification(t, ctx, client, expected, true)

	drifted := target
	drifted.Permissions = []string{"keys.write"}
	drifted.KeyAccess = KeyAccess{AllowedKeyPatterns: []string{"drifted-" + suffix + "-*"}}
	drifted.PolicyAccess = PolicyAccess{}
	if _, err := client.OnboardHuman(ctx, humanOnboardInput(drifted, "D6!Unused-"+suffix+"-Password")); err != nil {
		t.Fatalf("OnboardHuman induce grant and metadata drift: %v", err)
	}
	drift := integrationAwaitVerification(t, ctx, client, expected, false)
	if !hasIntegrationDrift(drift, "roles") || !hasIntegrationDrift(drift, "metadata."+keyAccessMetadataKey(namespace)) || !hasIntegrationDrift(drift, "metadata."+policyAccessMetadataKey(namespace)) {
		t.Fatalf("verification drift = %+v, want roles and both metadata fields", drift.Drift)
	}
	if _, err := client.OnboardHuman(ctx, humanOnboardInput(target, "E5!Unused-"+suffix+"-Password")); err != nil {
		t.Fatalf("OnboardHuman repair grant and metadata drift: %v", err)
	}
	integrationAwaitVerification(t, ctx, client, expected, true)

	driftWeb := webInput
	driftWeb.RedirectURIs = []string{"http://127.0.0.1:7861/obsolete/" + suffix}
	normalizedDrift, err := normalizeWebApplicationInput(driftWeb)
	if err != nil {
		t.Fatalf("normalize drifted web application: %v", err)
	}
	if _, err := client.EnsureWebApplication(ctx, driftWeb); err != nil {
		t.Fatalf("induce web application drift: %v", err)
	}
	integrationEventually(t, "web application drift", func() (bool, error) {
		application, err := client.lookupApplicationByName(ctx, bootstrap.ProjectID, webInput.Name)
		return err == nil && application != nil && reflect.DeepEqual(application.GetOidcConfiguration().GetRedirectUris(), normalizedDrift.redirectURIs), err
	})
	repairedWeb, err := client.EnsureWebApplication(ctx, webInput)
	if err != nil {
		t.Fatalf("EnsureWebApplication repair drift: %v", err)
	}
	if !repairedWeb.Updated || repairedWeb.Created {
		t.Fatalf("web drift repair result = %+v, want updated existing application", repairedWeb)
	}
	integrationAwaitVerification(t, ctx, client, expected, true)

	targetBeforeReset := integrationPasswordChanged(t, ctx, client, targetResult.UserID)
	sentinelBeforeReset := integrationPasswordChanged(t, ctx, client, sentinelResult.UserID)
	time.Sleep(10 * time.Millisecond)
	if err := client.ResetHumanPassword(ctx, ResetHumanPasswordInput{
		Username:               target.Username,
		NewPassword:            "F4!Reset-" + suffix + "-Password",
		PasswordChangeRequired: target.PasswordChangeRequired,
	}); err != nil {
		t.Fatalf("ResetHumanPassword: %v", err)
	}
	var targetAfterReset time.Time
	integrationEventually(t, "target password reset", func() (bool, error) {
		changed, err := integrationPasswordChangedValue(ctx, client, targetResult.UserID)
		targetAfterReset = changed
		return err == nil && changed.After(targetBeforeReset), err
	})
	sentinelAfterReset := integrationPasswordChanged(t, ctx, client, sentinelResult.UserID)
	if !sentinelAfterReset.Equal(sentinelBeforeReset) {
		t.Fatalf("target reset changed sentinel password timestamp: before=%s after=%s", sentinelBeforeReset, sentinelAfterReset)
	}
	if !targetAfterReset.After(targetBeforeReset) {
		t.Fatalf("target reset timestamp = %s, want after %s", targetAfterReset, targetBeforeReset)
	}

	machineUsername := "zga-machine-collision-" + suffix
	createdUsers = append(createdUsers, machineUsername)
	if _, err := client.Onboard(ctx, OnboardInput{Username: machineUsername, DisplayName: "Integration machine collision"}); err != nil {
		t.Fatalf("Onboard machine collision fixture: %v", err)
	}
	_, err = client.OnboardHuman(ctx, HumanOnboardInput{
		Username:        machineUsername,
		GivenName:       "Wrong",
		FamilyName:      "Type",
		Email:           "zga-collision+" + suffix + "@example.com",
		InitialPassword: "G3!Collision-" + suffix + "-Password",
	})
	if !errors.Is(err, ErrUserTypeMismatch) {
		t.Fatalf("OnboardHuman machine collision error = %v, want ErrUserTypeMismatch", err)
	}

	applicationCollisionName := "zga-api-collision-" + suffix
	if _, err := client.ensureAPIApplication(ctx, bootstrap.ProjectID, applicationCollisionName); err != nil {
		t.Fatalf("create API application collision fixture: %v", err)
	}
	integrationEventually(t, "API application collision fixture", func() (bool, error) {
		application, err := client.lookupApplicationByName(ctx, bootstrap.ProjectID, applicationCollisionName)
		return application != nil, err
	})
	_, err = client.EnsureWebApplication(ctx, WebApplicationInput{
		Name:         applicationCollisionName,
		RedirectURIs: []string{"http://127.0.0.1:7861/collision/" + suffix},
		DevMode:      true,
	})
	if !errors.Is(err, ErrApplicationTypeMismatch) {
		t.Fatalf("EnsureWebApplication type collision error = %v, want ErrApplicationTypeMismatch", err)
	}
}

func integrationAdminConfig(t *testing.T) Config {
	t.Helper()
	pat := strings.TrimSpace(os.Getenv("ZITADEL_ADMIN_PAT"))
	domain := strings.TrimSpace(os.Getenv("ZITADEL_DOMAIN"))
	port := strings.TrimSpace(os.Getenv("ZITADEL_PORT"))
	if pat == "" || domain == "" || port == "" {
		t.Skip("live Zitadel integration requires ZITADEL_ADMIN_PAT, ZITADEL_DOMAIN, and ZITADEL_PORT")
	}
	insecure := false
	if raw := strings.TrimSpace(os.Getenv("ZITADEL_INSECURE")); raw != "" {
		var err error
		insecure, err = strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("ZITADEL_INSECURE must be a boolean: %v", err)
		}
	}
	return Config{Domain: domain, Port: port, Insecure: insecure, PAT: pat}
}

func integrationSuffix(t *testing.T) string {
	t.Helper()
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("generate integration resource suffix: %v", err)
	}
	return hex.EncodeToString(random)
}

func humanOnboardInput(configuration HumanConfiguration, password string) HumanOnboardInput {
	return HumanOnboardInput{
		Username:               configuration.Username,
		GivenName:              configuration.GivenName,
		FamilyName:             configuration.FamilyName,
		DisplayName:            configuration.DisplayName,
		Email:                  configuration.Email,
		InitialPassword:        password,
		PasswordChangeRequired: configuration.PasswordChangeRequired,
		EmailVerified:          configuration.EmailVerified,
		Permissions:            append([]string(nil), configuration.Permissions...),
		KeyAccess:              configuration.KeyAccess,
		PolicyAccess:           configuration.PolicyAccess,
	}
}

func integrationPasswordChanged(t *testing.T, ctx context.Context, client *Client, userID string) time.Time {
	t.Helper()
	changed, err := integrationPasswordChangedValue(ctx, client, userID)
	if err != nil {
		t.Fatal(err)
	}
	if changed.IsZero() {
		t.Fatal("Zitadel returned an empty password-changed timestamp")
	}
	return changed
}

func integrationPasswordChangedValue(ctx context.Context, client *Client, userID string) (time.Time, error) {
	response, err := client.api.users.GetUserByID(ctx, &userV2.GetUserByIDRequest{UserId: userID})
	if err != nil {
		return time.Time{}, fmt.Errorf("GetUserByID(%s): %w", userID, err)
	}
	if response.GetUser() == nil || response.GetUser().GetHuman() == nil || response.GetUser().GetHuman().GetPasswordChanged() == nil {
		return time.Time{}, fmt.Errorf("GetUserByID(%s): password-changed timestamp is missing", userID)
	}
	return response.GetUser().GetHuman().GetPasswordChanged().AsTime(), nil
}

func integrationAwaitVerification(t *testing.T, ctx context.Context, client *Client, input HumanAuthConfigurationInput, current bool) *HumanAuthConfigurationResult {
	t.Helper()
	var result *HumanAuthConfigurationResult
	integrationEventually(t, fmt.Sprintf("verification current=%v", current), func() (bool, error) {
		var err error
		result, err = client.VerifyHumanAuthConfiguration(ctx, input)
		return err == nil && result.Current == current, err
	})
	return result
}

func integrationEventually(t *testing.T, description string, check func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for {
		ok, err := check()
		if ok {
			return
		}
		if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %v", description, lastErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func hasIntegrationDrift(result *HumanAuthConfigurationResult, field string) bool {
	for _, drift := range result.Drift {
		if drift.Field == field {
			return true
		}
	}
	return false
}

type integrationProjectDeleter interface {
	DeleteProject(context.Context, *projV2.DeleteProjectRequest, ...grpc.CallOption) (*projV2.DeleteProjectResponse, error)
}

type integrationActionDeleter interface {
	DeleteAction(context.Context, *management.DeleteActionRequest, ...grpc.CallOption) (*management.DeleteActionResponse, error)
}

func cleanupIntegrationResources(t *testing.T, client *Client, projectID, actionID string, usernames []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, username := range usernames {
		if err := client.Revoke(ctx, username, DeleteUser); err != nil {
			t.Errorf("cleanup user %q: %v", username, err)
		}
	}
	flow, err := client.api.management.GetFlow(ctx, &management.GetFlowRequest{Type: humanTokenFlowType})
	if err != nil {
		t.Errorf("cleanup flow: %v", err)
	} else {
		actionIDs := make([]string, 0)
		for _, trigger := range flow.GetFlow().GetTriggerActions() {
			if trigger.GetTriggerType().GetId() != humanTokenTriggerType {
				continue
			}
			for _, action := range trigger.GetActions() {
				if action.GetId() != "" && action.GetId() != actionID {
					actionIDs = append(actionIDs, action.GetId())
				}
			}
		}
		if _, err := client.api.management.SetTriggerActions(ctx, &management.SetTriggerActionsRequest{
			FlowType: humanTokenFlowType, TriggerType: humanTokenTriggerType, ActionIds: actionIDs,
		}); err != nil {
			t.Errorf("cleanup action trigger: %v", err)
		}
	}
	if deleter, ok := client.api.management.(integrationActionDeleter); ok {
		if _, err := deleter.DeleteAction(ctx, &management.DeleteActionRequest{Id: actionID}); err != nil && !isStatusCode(err, codes.NotFound) {
			t.Errorf("cleanup action: %v", err)
		}
	} else {
		t.Error("management service does not support action cleanup")
	}
	if deleter, ok := client.api.projects.(integrationProjectDeleter); ok {
		if _, err := deleter.DeleteProject(ctx, &projV2.DeleteProjectRequest{ProjectId: projectID}); err != nil && !isStatusCode(err, codes.NotFound) {
			t.Errorf("cleanup project: %v", err)
		}
	} else {
		t.Error("project service does not support project cleanup")
	}
}
