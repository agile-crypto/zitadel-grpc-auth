package admin

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"unicode"
)

// validNamespace restricts the characters allowed in a claim namespace. The
// rendered action script embeds the namespace verbatim inside JavaScript
// string literals; restricting the character set is the simplest way to
// guarantee no quoting/escape sequences can break out of those literals.
func validateNamespace(namespace string) error {
	if namespace == "" {
		return fmt.Errorf("admin: namespace must not be empty")
	}
	for _, r := range namespace {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == ':' || r == '-' || r == '_' || r == '.':
		default:
			return fmt.Errorf("admin: namespace %q contains disallowed character %q (allowed: alphanumerics and :-_.)", namespace, r)
		}
	}
	return nil
}

var actionTemplate = template.Must(template.New("action").Parse(`function {{.ActionName}}(ctx, api) {
  var permissions = [];
  try {
    var grants = ctx.v1.user.grants;
    if (grants && grants.count > 0 && grants.grants) {
      grants.grants.forEach(function (grant) {
        if (!grant.roles) return;
        grant.roles.forEach(function (role) {
          if (permissions.indexOf(role) === -1) permissions.push(role);
        });
      });
    }
  } catch (e) {}
  api.v1.claims.setClaim('{{.Namespace}}:permissions', permissions);

  var allowedKeys = [], denyKeys = [];
  var allowedPolicies = [], denyPolicies = [];
  try {
    var md = ctx.v1.user.getMetadata();
    if (md && md.count > 0 && md.metadata) {
      md.metadata.forEach(function (m) {
        if (m.key === '{{.Namespace}}:key_access' && m.value) {
          if (m.value.allowed_key_patterns) allowedKeys = m.value.allowed_key_patterns;
          if (m.value.deny_key_patterns) denyKeys = m.value.deny_key_patterns;
        } else if (m.key === '{{.Namespace}}:policy_access' && m.value) {
          if (m.value.allowed_policy_patterns) allowedPolicies = m.value.allowed_policy_patterns;
          if (m.value.deny_policy_patterns) denyPolicies = m.value.deny_policy_patterns;
        }
      });
    }
  } catch (e) {}
  api.v1.claims.setClaim('{{.Namespace}}:allowed_key_patterns', allowedKeys);
  api.v1.claims.setClaim('{{.Namespace}}:deny_key_patterns', denyKeys);
  api.v1.claims.setClaim('{{.Namespace}}:allowed_policy_patterns', allowedPolicies);
  api.v1.claims.setClaim('{{.Namespace}}:deny_policy_patterns', denyPolicies);
}`))

func RenderActionScript(namespace string) (string, error) {
	namespace = normalizeNamespace(namespace, "")
	if err := validateNamespace(namespace); err != nil {
		return "", err
	}
	var out bytes.Buffer
	err := actionTemplate.Execute(&out, map[string]string{
		"Namespace":  namespace,
		"ActionName": actionNameForNamespace(namespace),
	})
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

func actionNameForNamespace(namespace string) string {
	namespace = normalizeNamespace(namespace, "")
	var b strings.Builder
	b.WriteString("inject")
	upper := true
	for _, r := range namespace {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			upper = true
			continue
		}
		if upper {
			b.WriteRune(unicode.ToUpper(r))
			upper = false
			continue
		}
		b.WriteRune(r)
	}
	b.WriteString("Claims")
	return b.String()
}
