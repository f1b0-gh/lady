use ladyboot::artifact::{plan, publish, ArtifactRequest, Target};
use std::{fs, os::unix::fs::symlink};

#[test]
fn publication_preserves_existing_files_and_rejects_links() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let output = temp.path().join("lock.json");
    publish(&output, &serde_json::json!({"revision":1}), false)?;
    let before = fs::read(&output)?;
    assert!(publish(&output, &serde_json::json!({"revision":2}), false).is_err());
    assert_eq!(fs::read(&output)?, before);
    let link = temp.path().join("link.json");
    symlink(&output, &link)?;
    for replace in [false, true] {
        assert!(publish(&link, &serde_json::json!({"revision":2}), replace).is_err());
        assert_eq!(fs::read(&output)?, before);
    }
    let directory_link = temp.path().join("directory-link");
    symlink(temp.path(), &directory_link)?;
    assert!(publish(
        &directory_link.join("new.json"),
        &serde_json::json!({}),
        false
    )
    .is_err());
    publish(&output, &serde_json::json!({"revision":2}), true)?;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&output)?)?["revision"],
        2
    );
    Ok(())
}

#[test]
fn malformed_locks_are_rejected_before_evaluating_recipes() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = tempfile::tempdir()?;
    let lock = temp.path().join("invalid.json");
    let request = ArtifactRequest {
        config: temp.path().join("missing.ncl"),
        resources: temp.path().join("missing-recipes"),
    };
    for value in [
        r#"{"schema_version":1,"schema_version":2}"#,
        r#"{"schema_version":1,"profile":"bootc","configuration":{},"inputs_sha256":{},"evaluator":"unused","modules_sha256":{},"unexpected":true}"#,
    ] {
        fs::write(&lock, value)?;
        let error = match plan(&request, &lock, Target::Rootfs) {
            Err(error) => error,
            Ok(_) => return Err("malformed lock accepted".into()),
        };
        assert!(
            matches!(
                error,
                nickel_util::error::Error::InvalidInput { .. } | nickel_util::error::Error::Json(_)
            ),
            "must reject JSON before opening recipes: {error}"
        );
        assert_eq!(fs::read_to_string(&lock)?, value);
    }
    Ok(())
}
