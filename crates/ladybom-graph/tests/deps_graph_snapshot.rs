use ladybom::files;
use ladybom_graph as graph;
use serde_json::Value;
use std::{fs, path::Path};

#[test]
fn reads_historical_parquet_snapshot_without_rewriting() -> Result<(), Box<dyn std::error::Error>> {
    // Exported with Parquet 56.2.1 from the synthetic examples/explorer-demo/after inputs.
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parquet-56.2.1");
    let manifest = fs::read(fixture.join("manifest.json"))?;
    assert_eq!(
        files::hash(&manifest),
        "ffedab52fc1c7bf75a6a10b5bf185a818045d0f261def2889a989c3588566834"
    );
    let metadata: Value = serde_json::from_slice(&manifest)?;
    let records = metadata["files"]
        .as_object()
        .ok_or("fixture file records")?;
    let temporary = tempfile::tempdir()?;
    let snapshot = temporary.path();
    fs::write(snapshot.join("manifest.json"), &manifest)?;
    for (name, record) in records {
        let path = snapshot.join(name);
        fs::create_dir_all(path.parent().ok_or("fixture file parent")?)?;
        let bytes = fs::read(fixture.join(name))?;
        assert_eq!(record["sha256"], files::hash(&bytes));
        fs::write(path, bytes)?;
    }

    let graph = graph::read_snapshot(snapshot)?;
    assert_eq!(graph.schema_version, 1);
    assert_eq!(graph.inventory.schema_version, 2);
    assert!(graph.complete());
    assert_eq!(graph.components.len(), 3);
    assert_eq!(graph.roots.len(), 2);
    let edges: Vec<_> = graph
        .dependencies
        .iter()
        .map(|edge| (edge.from.purl.as_str(), edge.to.purl.as_str()))
        .collect();
    assert_eq!(
        edges,
        [
            ("pkg:npm/demo-api@1.3.0", "pkg:npm/demo-shared@1.4.2"),
            ("pkg:npm/demo-web@2.1.0", "pkg:npm/demo-shared@1.4.2"),
        ]
    );
    assert_eq!(
        metadata["logical_sha256"],
        files::hash(&serde_json::to_vec(&graph)?)
    );
    assert_eq!(fs::read(snapshot.join("manifest.json"))?, manifest);
    for name in records.keys() {
        assert_eq!(
            fs::read(snapshot.join(name))?,
            fs::read(fixture.join(name))?
        );
    }

    let context = graph
        .contexts
        .keys()
        .next()
        .ok_or("fixture graph context")?;
    let path = snapshot.join(context).join("dependencies.parquet");
    let mut bytes = fs::read(&path)?;
    *bytes.first_mut().ok_or("fixture Parquet bytes")? ^= 1;
    fs::write(path, bytes)?;
    let error = graph::read_snapshot(snapshot)
        .err()
        .ok_or("must refuse changed Parquet bytes")?;
    assert!(error.to_string().contains("Digest mismatch"), "{error}");
    Ok(())
}
