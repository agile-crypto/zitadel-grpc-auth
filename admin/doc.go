// Package admin provisions and manages Zitadel state for a single service:
//
//   - bootstrap the project, API app, roles, and action that injects claims
//   - onboard machine users with role grants and metadata-backed resource scope
//   - onboard human users without resetting existing passwords
//   - explicitly reset a human password as a separate operator action
//   - reconcile the public Web/OIDC application used for Authorization Code
//     with PKCE
//   - report human-login configuration drift without returning secrets
//   - revoke grants or delete users later
//
// It uses the Zitadel Go SDK internally for all Zitadel interactions.
//
// # Security model
//
// The injected action publishes two distinct sources of authorization
// signal into the access token:
//
//  1. Project role grants → "<namespace>:permissions" (a deduplicated
//     string array). These are server-controlled: a user cannot grant
//     themselves a project role.
//
//  2. User metadata under "<namespace>:key_access" and
//     "<namespace>:policy_access" → the corresponding
//     "<namespace>:allowed_*_patterns" / "<namespace>:deny_*_patterns"
//     claims. These are read directly from user metadata.
//
// The metadata path is only safe if your Zitadel ACLs forbid users from
// writing their own metadata. Audit the USER_METADATA_WRITE permission on
// every role you grant and ensure it is denied on Self. If you cannot
// guarantee this, do not use the KeyAccess / PolicyAccess inputs of
// Onboard — encode resource scope into project role names instead and
// derive patterns from the permissions claim in your PolicyFunc.
//
// All inputs that flow into Zitadel state (namespace, permission keys,
// glob patterns) are validated against a restricted character set
// (alphanumerics plus a small punctuation allow-list) before any side
// effect, so they cannot smuggle quotes, control characters, or JS
// escapes into the rendered action script or stored metadata.
//
// # Hosted human login
//
// This package provisions human identities and the public OIDC application; it
// does not authenticate a username and password or implement an interactive
// login UI. Applications must send the user's browser to Zitadel's hosted login
// and use Authorization Code with PKCE. Zitadel does not provide a resource-owner
// password grant for exchanging credentials directly.
//
// OnboardHuman sends InitialPassword only when it creates a user. Reusing an
// existing human reconciles project roles and resource metadata but does not
// reset the password. Password changes therefore require an explicit call to
// ResetHumanPassword. VerifyHumanAuthConfiguration is read-only and excludes
// passwords from both its input and drift output.
package admin
