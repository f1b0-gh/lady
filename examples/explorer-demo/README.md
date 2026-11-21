# Explorer audit example

These hand-authored npm fixtures are synthetic inputs for static analysis.
The `demo-*` names do not identify tested packages. Do not run `npm install`
in either fixture. Neither lockfile represents a verified installation.
The `.fixture` suffix keeps these inputs out of Lady's own dependency inventory;
the preparation script copies them into a new directory with their usual names.

## Reproduce the static audit

From the Lady repository root, choose a new output directory outside the fixture:

```sh
export CARGO_TARGET_DIR="$PWD/target"
cargo build --locked -p ladybom-cli
cargo build --locked -p ladybom --features graph --example deps_explorer
demo_out="$(mktemp -d /tmp/ladybom-explorer.XXXXXX)"
sh examples/explorer-demo/prepare.sh "$demo_out/inputs"
./target/debug/examples/deps_explorer "$demo_out/inputs/before" "$demo_out/before"
./target/debug/examples/deps_explorer "$demo_out/inputs/after" "$demo_out/after"
./target/debug/ladybom graph alignment --snapshot "$demo_out/before/snapshot"
./target/debug/ladybom graph alignment-plan --snapshot "$demo_out/before/snapshot" --markdown
./target/debug/ladybom graph diff --before "$demo_out/before/snapshot" --after "$demo_out/after/snapshot"
./target/debug/ladybom graph alignment --snapshot "$demo_out/after/snapshot"
```

Both snapshots have complete static graph coverage for these inputs. Before:
four package nodes, two dependency edges, two roots, and two versions of
`demo-shared`. After: three package nodes, two dependency edges and two roots.
The diff removes `demo-shared@1.2.3` from the API's nested installation scope
and redirects its incoming edge to the existing `demo-shared@1.4.2`.

| Input | Declared constraint | Locked version before |
| --- | --- | --- |
| Root → `demo-api` | `^1.0.0` | `1.3.0` |
| Root → `demo-web` | `^2.0.0` | `2.1.0` |
| API → `demo-shared` | `^1.2.0` | `1.2.3` |
| Web → `demo-shared` | `^1.4.0` | `1.4.2` |

The manifest also declares Node `>=20`. Lower bounds describe requirements;
they do not establish an installed runtime or a tested minimum. The after
fixture illustrates a common version permitted by the two shown ranges, not
an approved remediation. It was authored directly, without a package manager.
For stable versions, `^1.2.0` and `^1.4.0` intersect at `>=1.4.0 <2.0.0`:
`1.4.0` is the common declared lower bound; `1.4.2` is the observed after version.
Neither value is established as a tested or security-approved minimum.
Alignment alone does not assess advisories, compatibility or build equivalence.
The direct declarations remain ranges, so `alignment --check` still fails the
exact-pin policy even after the version divergence disappears.

## Reproduce the Explorer view

The [Ladybom guide screenshot](../../crates/ladybom-cli/README.md#inspect-dependency-differences) uses the unmodified UI from
[Ladybug Explorer revision `d132ba5`](https://github.com/LadybugDB/explorer/tree/d132ba5da9b9db24771e0c97376eeab6cf301c33)
and its own `@ladybugdb/core` **0.19.1**. Explorer is MIT-licensed; its
[license](https://github.com/LadybugDB/explorer/blob/d132ba5da9b9db24771e0c97376eeab6cf301c33/LICENSE)
applies to the depicted interface. Its `package-lock.json` SHA-256 is
`dbded0398bd4f0c1e850c68c3844190eb002c9b7c0360594557ae2b565cd6f07`.

Obtain that exact upstream revision in a separate directory, install its locked
dependencies with `npm ci`, and build with `npm run build` following the
[upstream prerequisites](https://github.com/LadybugDB/explorer/tree/d132ba5da9b9db24771e0c97376eeab6cf301c33#development-with-ladybug-compiled-from-source).
The capture build disabled worker parallelism, third-party transpilation,
minification and source maps, and bundled only Monaco's JSON language worker
(Explorer registers Cypher separately). These build settings reduce memory use
in modern Chrome; no UI source was changed.
This setup explicitly downloads and executes trusted Explorer tooling; the
Ladybom scan above does neither.

Set `explorer_checkout` to its absolute directory, then import with its engine:

```sh
node examples/explorer-demo/import.cjs "$explorer_checkout" \
  "$demo_out/before/explorer" "$demo_out/demo.lbdb"
```

The importer refuses an existing destination and executes the exporter's
`load.cypher`. Expected import counts: four `Package` nodes, one `Project`
node, two `Depends` edges, and two `Requires` edges. This script is for the
trusted generated demo CSV and Cypher, not arbitrary imported scripts.

Start the upstream server with the supplied loopback launcher:

```sh
node examples/explorer-demo/serve.cjs "$explorer_checkout" "$demo_out"
```

Open `http://127.0.0.1:8000`. The launcher sets `MODE=READ_ONLY`, opens
`demo.lbdb`, limits the buffer pool to 256 MiB and uses one engine core.
It changes only the server's listen address, leaving upstream UI and query
handling intact. Stop it with Ctrl+C. In Explorer's query editor, execute:

```cypher
MATCH (project:Project)-[root:Requires]->(parent:Package)-[dependency:Depends]->(shared:Package)
RETURN project, root, parent, dependency, shared;
```

Choose the graph view, with `Package` captions set to `label` (size 160) and
`Project` captions to `manifest` (size 130). The screenshot uses light mode,
the maximized query cell and its overview panel, captured directly from Chrome
156 at 1440 × 913 pixels. The graph shows the two parent paths and both shared
versions. Explorer's database is
rebuilt from CSV separately: it is not the immutable snapshot and is not
assumed compatible with Ladybom's qualified native CLI engine **0.17.1**.

For a real change, collect complete parent constraints, check current advisories
across the maintained scope, resolve in an authorized environment, and test the
consumers before comparing new snapshots. See the
[graph and validation guide](../../docs/dependency-graphs.md).
