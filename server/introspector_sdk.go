package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	oauthz "github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"

	auth "github.ibm.com/citius/zitadel-grpc-auth"
)

type sdkIntrospector struct {
	authorizer *authorization.Authorizer[*oauthz.IntrospectionContext]
}

// NewSDKIntrospector builds an Introspector using the Zitadel Go SDK's
// introspection verifier. It is the default implementation used by New when no
// custom Introspector is supplied.
func NewSDKIntrospector(issuer, clientID, clientSecret string, insecure bool) (Introspector, error) {
	domain, port, err := parseIssuerForSDK(issuer)
	if err != nil {
		return nil, fmt.Errorf("introspect: parse issuer: %w", err)
	}

	var opts []zitadel.Option
	if insecure {
		opts = append(opts, zitadel.WithInsecure(port))
	} else {
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("introspect: invalid issuer port %q: %w", port, err)
		}
		opts = append(opts, zitadel.WithPort(uint16(parsedPort)))
	}

	z := zitadel.New(domain, opts...)
	authN := oauthz.ClientIDSecretIntrospectionAuthentication(clientID, clientSecret)
	authorizer, err := authorization.New(context.Background(), z, oauthz.WithIntrospection[*oauthz.IntrospectionContext](authN))
	if err != nil {
		return nil, fmt.Errorf("introspect: create SDK authorizer: %w", err)
	}

	return &sdkIntrospector{authorizer: authorizer}, nil
}

func (s *sdkIntrospector) Introspect(ctx context.Context, token string) (*auth.Claims, time.Time, error) {
	intro, err := s.authorizer.CheckAuthorization(ctx, bearerValue(token))
	if err != nil {
		var unauthorized *authorization.UnauthorizedErr
		if errors.As(err, &unauthorized) {
			return nil, time.Time{}, auth.Unauthenticated("token not active")
		}
		return nil, time.Time{}, fmt.Errorf("introspect: %w", err)
	}

	claims := auth.NewClaims(introspectionClaims(intro))
	if !claims.Active() {
		return claims, time.Time{}, auth.Unauthenticated("token not active")
	}
	return claims, intro.Expiration.AsTime(), nil
}

func parseIssuerForSDK(issuer string) (domain, port string, err error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", "", err
	}
	if u.Hostname() == "" {
		return "", "", fmt.Errorf("issuer %q has no host", issuer)
	}
	if u.Path != "" && u.Path != "/" {
		return "", "", fmt.Errorf("issuer %q must not contain a path", issuer)
	}
	domain = u.Hostname()
	port = u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		default:
			port = "443"
		}
	}
	return domain, port, nil
}

func bearerValue(token string) string {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		return token
	}
	return "Bearer " + token
}

func introspectionClaims(intro *oauthz.IntrospectionContext) map[string]any {
	out := make(map[string]any, len(intro.Claims)+8)
	for key, value := range intro.Claims {
		out[key] = value
	}
	out["active"] = intro.Active
	if intro.Subject != "" {
		out["sub"] = intro.Subject
	}
	if intro.Username != "" {
		out["username"] = intro.Username
	}
	if intro.Issuer != "" {
		out["iss"] = intro.Issuer
	}
	if intro.ClientID != "" {
		out["client_id"] = intro.ClientID
	}
	if intro.TokenType != "" {
		out["token_type"] = intro.TokenType
	}
	if exp := intro.Expiration.AsTime(); !exp.IsZero() {
		out["exp"] = exp.Unix()
	}
	if issuedAt := intro.IssuedAt.AsTime(); !issuedAt.IsZero() {
		out["iat"] = issuedAt.Unix()
	}
	if len(intro.Audience) > 0 {
		aud := make([]string, 0, len(intro.Audience))
		for _, item := range intro.Audience {
			aud = append(aud, string(item))
		}
		out["aud"] = aud
	}
	return out
}