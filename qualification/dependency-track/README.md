# Dependency-Track qualification instance

This recipe starts the **Dependency-Track 5.2.1 API**, without a web UI, and
PostgreSQL in the `ladybom-interop` Docker project. It supports explicit synthetic
Ladybom tests. It does not establish inventory completeness, import fidelity
or current advisory coverage. No SBOM or VEX is imported at startup.

## Provenance and pinned images

The recipe starts from the [official quickstart](https://github.com/DependencyTrack/docs/blob/7c10127b96cabc70dc5f7a7d939604ebb5cab6b7/docs/tutorials/docker-compose.quickstart.yml)
at revision `7c10127b96cabc70dc5f7a7d939604ebb5cab6b7`, dated October 25, 2026.
Registry indexes were checked with `docker buildx imagetools inspect` on
November 5, 2026; downloaded digests were checked with `docker image inspect`.

| Image | Index digest | linux/amd64 manifest |
| --- | --- | --- |
| `dependencytrack/apiserver:5.2.1` | `sha256:a7ce7a42928c6c03e94e8255e2ee871f5268f55b638a69729cae7afc47ef43b8` | `sha256:e397bc147be419a9f902ba427cb6d737dbc6567e8cda0d449e47a1a41184533b` |
| `postgres:18-alpine`, resolved to `18.6-alpine3.24` | `sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5` | `sha256:3b0ef735388b2cb097fc29b8bb421d86d57d0ddbe7aa1fbd6493e06d65028503` |

The PostgreSQL manifest declares build revision
`e00e1bd34ec5c8a8e7ad89b273b3d42efaf6d5bc`, path `18/alpine3.24` in
[docker-library/postgres](https://github.com/docker-library/postgres/tree/e00e1bd34ec5c8a8e7ad89b273b3d42efaf6d5bc/18/alpine3.24).
These pins make the images reproducible; they are not a security advisory
assessment of their transitive packages.

## Start the instance

Run from the Lady root. Before the first startup, check that no
`ladybom-interop*` containers, networks or volumes exist and that ports
18081/19081 are available. Do not adopt existing state; choose a different
project name and ports if needed. The commands below reuse state only when
the operator deliberately resumes this same instance.

Create a synthetic password in a private file without displaying it:

```sh
python3 - <<'PY'
import os, secrets
fd = os.open('/tmp/ladybom-interop.env', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write('LADYBOM_DTRACK_DATABASE_PASSWORD=' + secrets.token_hex(24) + '\n')
PY
docker compose --env-file /tmp/ladybom-interop.env -f qualification/dependency-track/compose.yaml config --quiet
docker compose --env-file /tmp/ladybom-interop.env -f qualification/dependency-track/compose.yaml pull
docker compose --env-file /tmp/ladybom-interop.env -f qualification/dependency-track/compose.yaml up -d --no-recreate
```

The API is limited to 2 GiB of RAM and PostgreSQL to 512 MiB, suitable only for
the small synthetic dataset. PostgreSQL has no host port. No host directory,
Docker socket, personal secret or Nix daemon is mounted. The new
`ladybom-interop_apiserver-data` and `ladybom-interop_postgres-data` volumes
retain state.

The API listens on `127.0.0.1:18081`; the management server listens on
`127.0.0.1:19081`. PostgreSQL stays on the internal network. A separate bridge
network gives the API access to its published ports: on the qualification host,
Docker did not expose them with only the `internal: true` network.

Settings from the [5.2.1 release properties](https://github.com/DependencyTrack/dependency-track/blob/5.2.1/apiserver/src/main/resources/application.properties):

- `DT_TASK_SCHEDULER_ENABLED=false` disables periodic tasks, including mirrors
  and telemetry. Asynchronous processing remains active for explicit imports.
- `DT_TELEMETRY_SUBMISSION_DEFAULT_ENABLED=false` prevents initial telemetry
  activation on a new database. It does not override an already stored value.
- `DT_OUTBOUND_ALLOWED_DESTINATIONS=127.0.0.1` restricts application client
  destinations. It does not block database connections or the product's
  documented exceptions, and is not general container network confinement.

Check feeds and analyzers configured in the database separately before testing.
Disabled scheduling and failed mirrors do not establish advisory completeness.

## Check readiness and initialize the local account

```sh
curl -fsSL http://127.0.0.1:19081/health/ready
curl -fsSL http://127.0.0.1:18081/api/version
python3 qualification/dependency-track/bootstrap-admin.py --credentials /tmp/ladybom-interop-admin.json
```

Wait for `status: UP` and check the version before initialization. The script
changes the initial password only for this local instance and saves synthetic
credentials and a `bearer_token` in a JSON file with mode `0600`. It does not
print them and refuses to overwrite an existing file. The file works with the
qualification driver; do not commit it or attach it to public results. If the
password change succeeds but login fails, the private password remains available
for another login attempt. Preparation and qualification clients ignore
environment proxies and refuse redirects to keep credentials on the local endpoint.

## Run the synthetic tests

Preparation uses no network and runs no project scripts. Qualification then
performs explicit writes to new synthetic projects in this instance and retains
API responses. Use Python from the [pinned validation environment](../../docs/ladybom-interop.md#offline-validation-and-import-comparison)
with all required format validators.

```sh
cargo build -p ladybom-cli --locked
python3 tests/prepare_ladybom_qualification.py --output /tmp/ladybom-qualification-inputs
python3 tests/qualify_dependency_track.py --credentials /tmp/ladybom-interop-admin.json --inputs /tmp/ladybom-qualification-inputs --output /tmp/ladybom-qualification-results
```

Output directories must be new. Exit code 0 means the driver's limited assertions
passed, not that imports are fully faithful: `summary.json` remains
`qualification: partial` and describes losses. Keep its responses and hashes
with the observed image/version, including merged contexts and coverage losses.

## Stop and retain state

```sh
docker compose --env-file /tmp/ladybom-interop.env -f qualification/dependency-track/compose.yaml stop
```

Stopping retains containers, volumes and credentials. This recipe performs no
deletion and does not run `down -v`. Removing resources remains a separate,
explicit operation after retaining useful evidence.
