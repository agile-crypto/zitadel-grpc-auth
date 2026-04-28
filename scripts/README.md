# scripts/ — local Zitadel bootstrap & provisioning

One command brings up a fresh Zitadel instance via Docker Compose, provisions
it (project, roles, API app, service users, pre-userinfo action) using the
self-contained Go [setup-sdk/](setup-sdk/) helper, and emits an env file
ready for the [zitadel-grpc-auth](../README.md) integration tests and the
[greeter example](../examples/greeter/README.md).

## Files

| File | Purpose |
|---|---|
| [docker-compose.yml](docker-compose.yml) | Minimal Zitadel + Postgres stack (no Traefik, no TLS, port 8080) |
| [bootstrap-zitadel.sh](bootstrap-zitadel.sh) | up / down / reset orchestrator |
| [setup-sdk/main.go](setup-sdk/main.go) | Thin Go wrapper over [`admin.Bootstrap`](../admin/bootstrap.go) + [`admin.Onboard`](../admin/onboard.go) |
| [setup-sdk/go.mod](setup-sdk/go.mod) | Separate module, depends on the parent via a relative `replace` (so script-only deps like godotenv stay isolated) |
| `pat/admin.pat` (generated) | First-instance admin PAT, auto-provisioned by Zitadel on first boot |
| `.env` (generated) | PAT + endpoint vars consumed by [setup-sdk/main.go](setup-sdk/main.go) |
| `generated-config.json` (generated) | Full provisioning result (project_id, api_app, users, action_id) |
| `zitadel-test.env` (generated) | Sourceable env exporting `ZITADEL_ISSUER`, `INTROSPECT_ID`/`SECRET`, `PROJECT_ID`, and per-user `*_CLIENT_ID`/`*_CLIENT_SECRET` |

All generated artefacts are gitignored.

## Requirements

- Docker Engine 24+ with the Compose v2 plugin
- `jq`, `curl`, `go` (1.25+)

## Usage

```bash
# Bring everything up (compose → wait for ready → run setup-sdk → emit env file)
# default port 8080
./scripts/bootstrap-zitadel.sh

# or pick a different host port (since 8080 is busy on your machine)
ZITADEL_HOST_PORT=8090 ./scripts/bootstrap-zitadel.sh reset


# Source the env file and run integration tests
set -a && source scripts/zitadel-test.env && set +a
go test ./... -run Integration -count=1

# Tear it all down (stops containers, removes volumes, deletes generated artefacts)
./scripts/bootstrap-zitadel.sh down

# Clean reset (down + up)
./scripts/bootstrap-zitadel.sh reset
```

## How the admin PAT is bootstrapped

The Zitadel container runs `start-from-init` with these first-instance vars
(see [docker-compose.yml](docker-compose.yml)):

```
ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME=zitadel-admin-sa
ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE=2099-01-01T00:00:00Z
ZITADEL_FIRSTINSTANCE_PATPATH=/pat/admin.pat
```

On the very first boot Zitadel creates the machine user, mints a PAT, and
writes it to `/pat/admin.pat` inside the container. The compose file mounts
`./pat` on the host into `/pat`, so the bootstrap script can read the token
without any console interaction.

> These `FIRSTINSTANCE_*` vars only take effect on the **first** boot. Use
> `./bootstrap-zitadel.sh reset` if you need a clean slate.

## What gets provisioned

[setup-sdk/main.go](setup-sdk/main.go) creates everything the
zitadel-grpc-auth tests and the greeter example expect:

- **Project** `greeter-api` (with project-role assertion enabled)
- **Roles** `greeter:user`, `greeter:admin`
- **API application** `greeter-server` (BASIC auth) — its `client_id` /
  `client_secret` are what the server passes to
  [server.Config.IntrospectionClientID/Secret](../server/server.go) for
  `/oauth/v2/introspect` calls
- **Service users**
  - `alice` — `greeter:user`
  - `root`  — `greeter:user` + `greeter:admin`
  - `bob`   — no roles (negative-path tests)
- **Pre-userinfo action** (auto-named `injectUrnGreeterClaims`) — generated
  by [`admin.RenderActionScript`](../admin/action.go); copies the user's
  project-role grants into the custom claim `urn:greeter:permissions`,
  which the example's admin policy reads via
  `claims.HasStringInSlice("urn:greeter:permissions", "greeter:admin")`.
  Wired to flow `2` (token customisation) trigger `4` (pre userinfo
  creation) — the same trigger fires on introspection. The action also
  emits the `*_key_patterns` / `*_policy_patterns` claims (currently
  unused by the greeter example) so operators can experiment with the
  resource-scoping helpers without re-bootstrapping.

The resulting [generated-config.json](generated-config.json) is sliced into
[zitadel-test.env](zitadel-test.env) so tests and examples can pick up:

| Variable | Use |
|---|---|
| `INTROSPECT_ID` / `INTROSPECT_SECRET` | [server.Config](../server/server.go) introspection |
| `PROJECT_ID` | Optional project-bound introspection scope |
| `ALICE_CLIENT_ID` / `ALICE_CLIENT_SECRET` | [client.Config](../client/client.go) for the `greeter:user` user |
| `ROOT_CLIENT_ID`  / `ROOT_CLIENT_SECRET`  | Same, for the `greeter:admin` user |
| `BOB_CLIENT_ID`   / `BOB_CLIENT_SECRET`   | Same, for the unprivileged user |

## Running the greeter example against the bootstrapped instance

```bash
set -a && source scripts/zitadel-test.env && set +a

# If a previous run left a greeter server bound to :50061 it would still
# hold the OLD INTROSPECT_ID/SECRET and fail with "unauthorized_client"
# against the freshly-provisioned Zitadel — always start clean.
lsof -tiTCP:50061 -sTCP:LISTEN | xargs -r kill -9 2>/dev/null || true

# server (uses INTROSPECT_ID / INTROSPECT_SECRET) — backgrounded
go run ./examples/greeter/server &
SERVER_PID=$!

# `go run` first compiles, then execs the binary; the listen socket isn't
# bound until the server line "greeter listening on …" is printed. Wait
# for the port to actually accept connections before firing the client.
for _ in $(seq 1 30); do
  (echo > /dev/tcp/127.0.0.1/50061) >/dev/null 2>&1 && break
  sleep 0.5
done

# alice → Hello succeeds, Admin denied
CLIENT_ID=$ALICE_CLIENT_ID CLIENT_SECRET=$ALICE_CLIENT_SECRET \
  go run ./examples/greeter/client -op hello -name alice
CLIENT_ID=$ALICE_CLIENT_ID CLIENT_SECRET=$ALICE_CLIENT_SECRET \
  go run ./examples/greeter/client -op admin -name "rotate"   # PermissionDenied

# root → Admin succeeds
CLIENT_ID=$ROOT_CLIENT_ID CLIENT_SECRET=$ROOT_CLIENT_SECRET \
  go run ./examples/greeter/client -op admin -name "rotate"

# stop the backgrounded server when you're done
kill $SERVER_PID
```

> If you're typing these by hand, just run the server in one terminal and the
> client commands in another — the readiness loop only matters when you
> background the server in the same shell.

## Troubleshooting

- **"PAT was not written within 120s"** — `docker compose -p zga logs zitadel`
  and look for migration errors. If the volume contains an old database from
  a previous run, do a `reset`.
- **`setup-sdk` fails with a non-`AlreadyExists` Zitadel error** — the
  `admin` package is idempotent for project/role/action/user creation,
  so re-runs against the same instance are safe; if you hit a hard
  failure, capture the log and run `./bootstrap-zitadel.sh reset` for a
  clean slate.
- **Empty `*_CLIENT_SECRET` after a re-run** — Zitadel only surfaces the
  machine-user secret on first creation. `admin.Onboard` warns when this
  happens; do a `reset` if you need the secrets surfaced again.
- **Port 8080 already in use** — change the host-side port in
  [docker-compose.yml](docker-compose.yml) and update `ZITADEL_EXTERNALPORT`
  + `ZITADEL_ISSUER` accordingly.
- **`/debug/ready` 404** — older Zitadel images don't expose it; the script
  falls back to the PAT-file check, which is the real readiness signal.
