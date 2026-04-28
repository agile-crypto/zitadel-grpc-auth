// Package admin provisions and manages Zitadel state for a single service:
//
//   - bootstrap the project, API app, roles, and action that injects claims
//   - onboard machine users with role grants and metadata-backed resource scope
//   - revoke grants or delete those users later
//
// It uses the Zitadel Go SDK internally for all Zitadel interactions.
package admin
