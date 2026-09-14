package admin

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

type Config struct {
	Domain      string
	Port        string
	Insecure    bool
	OrgID       string
	Namespace   string
	ProjectID   string
	ProjectName string
	PAT         string
	JWTKeyPath  string
	Logger      *slog.Logger
}

type Client struct {
	api    adminServices
	cfg    Config
	logger *slog.Logger
}

type BootstrapInput struct {
	ProjectName    string
	ClaimNamespace string
	Operations     []Operation
}

type Operation struct {
	Method      string
	Permission  string
	DisplayName string
}

type BootstrapResult struct {
	ProjectID string
	APIApp    AppCredentials
	ActionID  string
}

type AppCredentials struct {
	ClientID     string
	ClientSecret string
}

type OnboardInput struct {
	Username     string
	DisplayName  string
	Permissions  []string
	KeyAccess    KeyAccess
	PolicyAccess PolicyAccess
}

// HumanOnboardInput describes an interactive user managed by Zitadel. It is
// intentionally separate from OnboardInput so callers cannot accidentally use
// a human password where a machine-user client secret is expected.
type HumanOnboardInput struct {
	Username               string
	GivenName              string
	FamilyName             string
	DisplayName            string
	Email                  string
	InitialPassword        string
	PasswordChangeRequired bool
	EmailVerified          bool
	Permissions            []string
	KeyAccess              KeyAccess
	PolicyAccess           PolicyAccess
}

type HumanOnboardResult struct {
	UserID    string
	LoginName string
	Created   bool
}

type ResetHumanPasswordInput struct {
	Username               string
	NewPassword            string
	PasswordChangeRequired bool
}

// WebApplicationInput declares the complete redirect URI configuration for a
// public OIDC web client using Authorization Code with PKCE.
type WebApplicationInput struct {
	Name                   string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	EnableRefreshTokens    bool
	DevMode                bool
}

// WebApplicationResult identifies a reconciled OIDC web application.
type WebApplicationResult struct {
	ApplicationID string
	ClientID      string
	Created       bool
	Updated       bool
}

type KeyAccess struct {
	AllowedKeyPatterns []string
	DenyKeyPatterns    []string
}

type PolicyAccess struct {
	AllowedPolicyPatterns []string
	DenyPolicyPatterns    []string
}

type OnboardResult struct {
	UserID       string
	ClientID     string
	ClientSecret string
}

type RevokeMode int

const (
	RevokeGrants RevokeMode = iota
	DeleteUser
)

func Bootstrap(ctx context.Context, c *Client, in BootstrapInput) (*BootstrapResult, error) {
	if c == nil {
		return nil, fmt.Errorf("admin.Bootstrap: nil client")
	}
	return c.Bootstrap(ctx, in)
}

func Onboard(ctx context.Context, c *Client, in OnboardInput) (*OnboardResult, error) {
	if c == nil {
		return nil, fmt.Errorf("admin.Onboard: nil client")
	}
	return c.Onboard(ctx, in)
}

func OnboardHuman(ctx context.Context, c *Client, in HumanOnboardInput) (*HumanOnboardResult, error) {
	if c == nil {
		return nil, fmt.Errorf("admin.OnboardHuman: nil client")
	}
	return c.OnboardHuman(ctx, in)
}

func ResetHumanPassword(ctx context.Context, c *Client, in ResetHumanPasswordInput) error {
	if c == nil {
		return fmt.Errorf("admin.ResetHumanPassword: nil client")
	}
	return c.ResetHumanPassword(ctx, in)
}

func EnsureWebApplication(ctx context.Context, c *Client, in WebApplicationInput) (*WebApplicationResult, error) {
	if c == nil {
		return nil, fmt.Errorf("admin.EnsureWebApplication: nil client")
	}
	return c.EnsureWebApplication(ctx, in)
}

func Revoke(ctx context.Context, c *Client, username string, mode RevokeMode) error {
	if c == nil {
		return fmt.Errorf("admin.Revoke: nil client")
	}
	return c.Revoke(ctx, username, mode)
}

func normalizeNamespace(explicit, fallback string) string {
	namespace := strings.TrimSpace(explicit)
	if namespace == "" {
		namespace = strings.TrimSpace(fallback)
	}
	if namespace == "" {
		return "urn:citius"
	}
	return namespace
}
