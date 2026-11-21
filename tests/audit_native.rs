//! Opt-in native probes. Requires the immutable audit-image.json of a built run.
use ladyshell::{
    audit::{
        collect,
        config::Limits,
        image::BuiltImage,
        journal::RunJournal,
        model::{Budget, InvocationStatus, Role, RunStatus},
        runtime::NativeRuntime,
        worker::WorkerRequest,
    },
    openshell::Backend,
};
use serde_json::json;
use std::{path::PathBuf, time::Duration};

#[test]
#[ignore = "Requires LADYSHELL_AUDIT_IMAGE and native OpenShell/Docker admission; creates and deletes owned resources"]
fn native_refusals_interruptions_and_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let image: BuiltImage =
        serde_json::from_slice(&std::fs::read(std::env::var("LADYSHELL_AUDIT_IMAGE")?)?)?;
    let parent = PathBuf::from(std::env::var("LADYSHELL_AUDIT_PROBES")?);
    ladyshell::state::create_directory(&parent)?;
    let limits = Limits {
        cpu_seconds: 10,
        memory_bytes: 1073741824,
        processes: 256,
        files: 128,
        disk_bytes: 1048576,
    };
    let runtime = NativeRuntime {
        backend: Backend::new(&json!({"gateway":"openshell","workspace":"default"}))?,
        image,
        limits: limits.clone(),
        provider: String::new(),
        account: String::new(),
    };
    let cases = [
        (
            "boundary",
            vec![
                "/bin/python3",
                "-c",
                r#"import os,socket
for path in ['/audit/source/forbidden','/etc/forbidden','/proc/1/fd/1']:
 try:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT,0o600);os.close(fd);raise AssertionError(path)
 except PermissionError: pass
s=socket.socket();s.settimeout(1)
try: s.connect(('1.1.1.1',443));raise AssertionError('network allowed')
except OSError: pass
try: os.setsid();raise AssertionError('session escape')
except PermissionError: pass
assert 'CODEX_AUTH_ACCESS_TOKEN' not in os.environ
print('boundaries-ok')"#,
            ],
            false,
        ),
        (
            "process-memory",
            vec![
                "/bin/python3",
                "-c",
                r#"import errno,os,signal
children=[]
try:
 for _ in range(512):
  child=os.fork()
  if child==0:
   signal.pause();os._exit(0)
  children.append(child)
except OSError as e: assert e.errno==errno.EAGAIN
finally:
 for child in children: os.kill(child,signal.SIGKILL)
 for child in children: os.waitpid(child,0)
assert 0<len(children)<256
try: bytearray(2*1024*1024*1024);raise AssertionError('memory unbounded')
except MemoryError: pass
print('process-memory-bounds-ok')"#,
            ],
            false,
        ),
        (
            "interrupt",
            vec![
                "/bin/bash",
                "-c",
                r#"kill -TERM "$PPID"; while :; do :; done"#,
            ],
            false,
        ),
        (
            "timeout",
            vec!["/bin/bash", "-c", "(while :; do :; done) & wait"],
            true,
        ),
        (
            "storage",
            vec![
                "/bin/python3",
                "-c",
                r#"import errno,os
count=0
try:
 while True:
  open('inode-'+str(count),'wb').close();count+=1
except OSError as e: assert e.errno==errno.ENOSPC
assert 0<count<=128
for i in range(count): os.unlink('inode-'+str(i))
written=0
try:
 with open('fill','wb',buffering=0) as f:
  while True: written+=f.write(b'x'*4096)
except OSError as e: assert e.errno in [errno.ENOSPC,errno.EFBIG]
assert 0<written<=1048576
print('storage-bounds-ok')"#,
            ],
            false,
        ),
    ];
    for (name, argv, timeout) in cases {
        let mut journal = RunJournal::create(
            &parent,
            &"b".repeat(64),
            Budget {
                invocations: 7,
                seconds: 60,
            },
        )?;
        journal.start()?;
        journal.begin_invocation("probe", Role::Verifier)?;
        let request = WorkerRequest {
            schema_version: 1,
            invocation_id: name.into(),
            command: argv.into_iter().map(str::to_owned).collect(),
            limits: limits.clone(),
            timeout_seconds: if timeout { 1 } else { 4 },
            sources: vec![],
            artifacts: vec![],
        };
        let result = (|| -> ladyshell::error::Result<()> {
            let execution = runtime.target(&mut journal, request, Duration::from_secs(30));
            if name == "interrupt" {
                return match execution {
                    Err(error) if error.to_string().contains("Worker interrupted") => Ok(()),
                    Err(error) => Err(error),
                    Ok(_) => Err(ladyshell::error::Error::InvalidInput {
                        message: "Interruption without receipt rejection".into(),
                    }),
                };
            }
            let stopped = execution?;
            let receipt = stopped.receipt();
            let valid = receipt.stopped
                && !receipt.output_limited
                && receipt.timed_out == timeout
                && (timeout || receipt.exit_code == 0);
            collect::collect_target(journal.directory(), "probe", name, stopped)?;
            if !valid {
                return Err(ladyshell::error::Error::InvalidInput {
                    message: format!(
                        "Probe {name} failed; evidence in {}",
                        journal.directory().display()
                    ),
                });
            }
            Ok(())
        })();
        let cleaned = runtime.cleanup(&mut journal);
        journal.finish_invocation(
            "probe",
            if result.is_ok() {
                InvocationStatus::Finished
            } else {
                InvocationStatus::Failed
            },
        )?;
        journal.finish(if result.is_ok() {
            RunStatus::Partial
        } else {
            RunStatus::Failed
        })?;
        assert!(journal.data().cleanup_verified, "{name}");
        cleaned?;
        result?;
    }
    Ok(())
}

#[test]
#[ignore = "Requires LADYSHELL_AUDIT_IMAGE, LADYSHELL_AUDIT_PROVIDER and native OpenShell credentials"]
fn native_agent_driver() -> Result<(), Box<dyn std::error::Error>> {
    let image: BuiltImage =
        serde_json::from_slice(&std::fs::read(std::env::var("LADYSHELL_AUDIT_IMAGE")?)?)?;
    let parent = PathBuf::from(std::env::var("LADYSHELL_AUDIT_PROBES")?);
    ladyshell::state::create_directory(&parent)?;
    let auth_root = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".codex")
        });
    let runtime = NativeRuntime {
        backend: Backend::new(&json!({"gateway":"openshell","workspace":"default"}))?,
        image,
        limits: Limits {
            cpu_seconds: 30,
            memory_bytes: 1073741824,
            processes: 256,
            files: 2048,
            disk_bytes: 268435456,
        },
        provider: std::env::var("LADYSHELL_AUDIT_PROVIDER")?,
        account: ladyshell::auth::host_account(&auth_root.join("auth.json"))?,
    };
    let mut journal = RunJournal::create(
        &parent,
        &"c".repeat(64),
        Budget {
            invocations: 7,
            seconds: 180,
        },
    )?;
    journal.start()?;
    journal.begin_invocation("driver-probe", Role::Recon)?;
    let result=runtime.agent(&mut journal,"driver-probe",br#"Native driver health check. Do not use tools. Return this JSON object: {"summary":"Native driver available","reviewed_paths":[],"candidates":[],"finding_json":null,"unresolved":[]}"#,Duration::from_secs(120));
    let cleaned = runtime.cleanup(&mut journal);
    journal.finish_invocation(
        "driver-probe",
        if result.is_ok() {
            InvocationStatus::Finished
        } else {
            InvocationStatus::Failed
        },
    )?;
    journal.finish(if result.is_ok() {
        RunStatus::Partial
    } else {
        RunStatus::Failed
    })?;
    cleaned?;
    let (response, raw) = result?;
    assert!(!response.summary.is_empty());
    collect::retain_agent(
        journal.directory(),
        "driver-probe",
        &raw,
        vec![runtime.image.codex_binary, "exec".into()],
    )?;
    assert!(journal.data().cleanup_verified);
    Ok(())
}
