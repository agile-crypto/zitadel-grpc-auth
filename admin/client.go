package admin

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	sdkclient "github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, fmt.Errorf("admin.NewClient: Domain is required")
	}
	if strings.TrimSpace(cfg.Port) == "" {
		cfg.Port = "443"
	}
	if strings.TrimSpace(cfg.Namespace) == "" {
		cfg.Namespace = "urn:citius"
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var authOpt sdkclient.TokenSourceInitializer
	switch {
	case strings.TrimSpace(cfg.PAT) != "":
		authOpt = sdkclient.PAT(cfg.PAT)
	case strings.TrimSpace(cfg.JWTKeyPath) != "":
		authOpt = sdkclient.DefaultServiceUserAuthentication(filepath.Clean(cfg.JWTKeyPath), sdkclient.ScopeZitadelAPI())
	default:
		return nil, fmt.Errorf("admin.NewClient: either PAT or JWTKeyPath is required")
	}

	var opts []zitadel.Option
	if cfg.Insecure {
		opts = append(opts, zitadel.WithInsecure(cfg.Port))
	} else {
		port, err := strconv.ParseUint(cfg.Port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("admin.NewClient: invalid port %q: %w", cfg.Port, err)
		}
		opts = append(opts, zitadel.WithPort(uint16(port)))
	}

	api, err := sdkclient.New(ctx, zitadel.New(cfg.Domain, opts...), sdkclient.WithAuth(authOpt))
	if err != nil {
		return nil, fmt.Errorf("admin.NewClient: %w", err)
	}

	return &Client{api: api, cfg: cfg, logger: logger}, nil
}

func (c *Client) Close() error {
	if c == nil || c.api == nil {
		return nil
	}
	return c.api.Close()
}
