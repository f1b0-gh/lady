use ladyshell::state::{read, SessionLock, StateLock};
#[test]
fn locks_are_nonblocking_and_sessions_block_replace_but_not_sync(
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let state = tmp.path().join("state");
    let lock = StateLock::acquire(&state)?;
    assert!(StateLock::acquire(&state).is_err());
    drop(lock);
    let _lock = StateLock::acquire(&state)?;
    let session = SessionLock::acquire(&state, false)?;
    assert!(SessionLock::acquire(&state, true).is_err());
    drop(session);
    let _exclusive = SessionLock::acquire(&state, true)?;
    assert!(read(&state.join("state.json"))?.is_none());
    std::fs::write(state.join("state.json"), "bad json")?;
    assert!(read(&state.join("state.json")).is_err());
    Ok(())
}
#[test]
fn rejects_state_directory_symlink() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    std::os::unix::fs::symlink("/tmp", tmp.path().join("link"))?;
    assert!(StateLock::acquire(&tmp.path().join("link")).is_err());
    Ok(())
}
