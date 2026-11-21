# ladybom-graph

A Clap-free Rust library for persisting and analyzing static graphs built by
[Ladybom](../ladybom/README.md). Import the graph model and projector from either
library. Snapshot storage, alignment policy, LadybugDB queries, usage analysis
and removal simulations live here. The default
[ladybom CLI](../ladybom-cli/README.md) includes these operations.

```rust,no_run
use ladybom::scan_project;
use ladybom_graph::{project, write_snapshot};
use std::path::Path;

let graph = project(scan_project(Path::new("/project"))?)?;
write_snapshot(&graph, Path::new("/state/new-snapshot"))?;
# Ok::<(), ladybom::error::Error>(())
```

Export and alignment run without a native engine. Traversal and simulation take
an explicit trusted LadybugDB 0.17.1 executable. The
[graph guide](../../docs/dependency-graphs.md) covers snapshot verification,
the Explorer example, usage analysis and removal validation.

## Rust API migration

For callers of the former `ladybom/graph` feature, depend on `ladybom-graph`
and import persistence and analysis functions from `ladybom_graph`. Import usage
analysis from `ladybom_graph::usage` and construct validation plans with
`ladybom_graph::prune_validation::plan`. The core retains `ladybom::graph::project`,
`diff`, the graph model and `ladybom::prune_validation::ValidationPlan`.
Snapshot schema version 1 and inventory schema version 2 retain their formats.
