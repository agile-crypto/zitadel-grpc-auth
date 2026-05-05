package admin

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	appV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/application/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	projV2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func (c *Client) Bootstrap(ctx context.Context, in BootstrapInput) (*BootstrapResult, error) {
	if strings.TrimSpace(in.ProjectName) == "" {
		return nil, fmt.Errorf("admin.Bootstrap: ProjectName is required")
	}
	if len(in.Operations) == 0 {
		return nil, fmt.Errorf("admin.Bootstrap: at least one operation is required")
	}
	for _, op := range in.Operations {
		if err := validatePermission(strings.TrimSpace(op.Permission)); err != nil {
			return nil, fmt.Errorf("admin.Bootstrap: %w", err)
		}
	}

	namespace := normalizeNamespace(in.ClaimNamespace, c.cfg.Namespace)
	orgID, err := c.resolveOrgID(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin.Bootstrap: resolve org: %w", err)
	}

	project, err := c.findProjectByName(ctx, orgID, in.ProjectName)
	if err != nil {
		return nil, fmt.Errorf("admin.Bootstrap: find project: %w", err)
	}
	if project == nil {
		resp, err := c.api.ProjectServiceV2().CreateProject(ctx, &projV2.CreateProjectRequest{
			OrganizationId:       orgID,
			Name:                 in.ProjectName,
			ProjectRoleAssertion: true,
		})
		if err != nil {
			return nil, fmt.Errorf("admin.Bootstrap: create project: %w", err)
		}
		project = &projV2.Project{ProjectId: resp.GetProjectId(), OrganizationId: orgID, Name: in.ProjectName, ProjectRoleAssertion: true}
	}

	operations := dedupeOperations(in.Operations)
	for _, op := range operations {
		displayName := strings.TrimSpace(op.DisplayName)
		if displayName == "" {
			displayName = op.Permission
		}
		_, err := c.api.ProjectServiceV2().AddProjectRole(ctx, &projV2.AddProjectRoleRequest{
			ProjectId:   project.GetProjectId(),
			RoleKey:     op.Permission,
			DisplayName: displayName,
		})
		if err != nil && !isStatusCode(err, codes.AlreadyExists) {
			return nil, fmt.Errorf("admin.Bootstrap: add project role %q: %w", op.Permission, err)
		}
	}

	appCreds, err := c.ensureAPIApplication(ctx, project.GetProjectId(), in.ProjectName+"-server")
	if err != nil {
		return nil, fmt.Errorf("admin.Bootstrap: ensure API application: %w", err)
	}

	script, err := RenderActionScript(namespace)
	if err != nil {
		return nil, fmt.Errorf("admin.Bootstrap: render action script: %w", err)
	}
	actionID, err := c.ensureAction(ctx, actionNameForNamespace(namespace), script)
	if err != nil {
		return nil, fmt.Errorf("admin.Bootstrap: ensure action: %w", err)
	}

	triggerActions, err := c.unionTriggerActions(ctx, "2", "4", actionID)
	if err != nil {
		return nil, fmt.Errorf("admin.Bootstrap: read trigger actions: %w", err)
	}
	_, err = c.api.ManagementService().SetTriggerActions(ctx, &management.SetTriggerActionsRequest{
		FlowType:    "2",
		TriggerType: "4",
		ActionIds:   triggerActions,
	})
	if err != nil {
		return nil, fmt.Errorf("admin.Bootstrap: wire trigger actions: %w", err)
	}

	c.logger.Info("bootstrapped Zitadel resources", "project_id", project.GetProjectId(), "action_id", actionID)
	return &BootstrapResult{ProjectID: project.GetProjectId(), APIApp: appCreds, ActionID: actionID}, nil
}

func dedupeOperations(operations []Operation) []Operation {
	seen := make(map[string]Operation, len(operations))
	for _, op := range operations {
		method := strings.TrimSpace(op.Method)
		permission := strings.TrimSpace(op.Permission)
		if method == "" || permission == "" {
			continue
		}
		seen[permission] = Operation{Method: method, Permission: permission, DisplayName: strings.TrimSpace(op.DisplayName)}
	}
	keys := make([]string, 0, len(seen))
	for permission := range seen {
		keys = append(keys, permission)
	}
	sort.Strings(keys)
	out := make([]Operation, 0, len(keys))
	for _, permission := range keys {
		out = append(out, seen[permission])
	}
	return out
}

func (c *Client) ensureAPIApplication(ctx context.Context, projectID, appName string) (AppCredentials, error) {
	resp, err := c.api.ApplicationServiceV2().ListApplications(ctx, &appV2.ListApplicationsRequest{})
	if err != nil {
		return AppCredentials{}, err
	}
	for _, app := range resp.GetApplications() {
		if app.GetProjectId() != projectID || app.GetName() != appName || app.GetApiConfiguration() == nil {
			continue
		}
		return AppCredentials{ClientID: app.GetApiConfiguration().GetClientId()}, nil
	}

	created, err := c.api.ApplicationServiceV2().CreateApplication(ctx, &appV2.CreateApplicationRequest{
		ProjectId: projectID,
		Name:      appName,
		ApplicationType: &appV2.CreateApplicationRequest_ApiConfiguration{
			ApiConfiguration: &appV2.CreateAPIApplicationRequest{AuthMethodType: appV2.APIAuthMethodType_API_AUTH_METHOD_TYPE_BASIC},
		},
	})
	if err != nil {
		return AppCredentials{}, err
	}
	apiCfg := created.GetApiConfiguration()
	return AppCredentials{ClientID: apiCfg.GetClientId(), ClientSecret: apiCfg.GetClientSecret()}, nil
}

func (c *Client) ensureAction(ctx context.Context, name, script string) (string, error) {
	resp, err := c.api.ManagementService().ListActions(ctx, &management.ListActionsRequest{})
	if err != nil {
		return "", err
	}
	for _, action := range resp.GetResult() {
		if action.GetName() != name {
			continue
		}
		if action.GetScript() != script {
			_, err := c.api.ManagementService().UpdateAction(ctx, &management.UpdateActionRequest{
				Id:            action.GetId(),
				Name:          name,
				Script:        script,
				Timeout:       durationpb.New(10 * time.Second),
				AllowedToFail: false,
			})
			if err != nil {
				return "", err
			}
		}
		return action.GetId(), nil
	}

	created, err := c.api.ManagementService().CreateAction(ctx, &management.CreateActionRequest{
		Name:          name,
		Script:        script,
		Timeout:       durationpb.New(10 * time.Second),
		AllowedToFail: false,
	})
	if err != nil {
		return "", err
	}
	return created.GetId(), nil
}

// unionTriggerActions returns the existing list of action IDs already wired
// to (flowType, triggerType), with actionID appended if it is not already
// present. This protects operators who have manually wired additional
// actions to the same trigger from having those silently dropped by our
// idempotent re-bootstrap.
func (c *Client) unionTriggerActions(ctx context.Context, flowType, triggerType, actionID string) ([]string, error) {
	resp, err := c.api.ManagementService().GetFlow(ctx, &management.GetFlowRequest{Type: flowType})
	if err != nil {
		// If the flow can't be read, fall back to wiring just our action;
		// the SetTriggerActions call below will surface any real error.
		return []string{actionID}, nil
	}
	existing := []string{actionID}
	seen := map[string]struct{}{actionID: {}}
	for _, ta := range resp.GetFlow().GetTriggerActions() {
		if ta.GetTriggerType().GetId() != triggerType {
			continue
		}
		for _, a := range ta.GetActions() {
			id := a.GetId()
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			existing = append(existing, id)
		}
	}
	return existing, nil
}

func isStatusCode(err error, code codes.Code) bool {
	return status.Code(err) == code
}
