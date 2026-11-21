use ladyshell::error::Error;
use nickel_util::error::Error as CoreError;
use std::{
    error::Error as StdError, os::unix::process::ExitStatusExt, process::ExitStatus, time::Duration,
};

#[test]
fn core_causes_remain_typed_through_application_context() -> Result<(), Box<dyn StdError>> {
    let core = CoreError::ProcessSpawn {
        program: "missing-evaluator".into(),
        source: std::io::Error::from_raw_os_error(libc::ENOENT),
    }
    .context("evaluation input");
    assert!(core
        .source()
        .is_some_and(|cause| cause.is::<Box<CoreError>>()));
    let application: Error = core.into();
    assert!(
        matches!(&application, Error::Context { message, .. } if message == "evaluation input")
    );
    let process = application
        .source()
        .and_then(|cause| cause.downcast_ref::<Box<Error>>())
        .ok_or("lost typed application source")?;
    assert!(
        matches!(process.as_ref(), Error::ProcessSpawn { program, .. } if program == "missing-evaluator")
    );
    let io = process
        .source()
        .and_then(|cause| cause.downcast_ref::<std::io::Error>())
        .ok_or("lost I/O cause")?;
    assert_eq!(io.raw_os_error(), Some(libc::ENOENT));
    assert_eq!(application.exit_code(), 1);
    Ok(())
}

#[test]
fn evaluation_conversion_preserves_validation_and_operational_exit_codes() {
    let rejected: Error = CoreError::Nickel {
        source: Box::new(CoreError::ProcessExit {
            program: "nickel".into(),
            status: ExitStatus::from_raw(7 << 8),
            stderr: "contract rejected".into(),
        }),
    }
    .context("requested evaluation")
    .into();
    assert_eq!(rejected.exit_code(), 2);
    assert!(matches!(&rejected, Error::Context { source, .. }
        if matches!(source.as_ref(), Error::Nickel { source }
            if matches!(source.as_ref(), Error::ProcessExit { status, stderr, .. }
                if status.code() == Some(7) && stderr == "contract rejected"))));
    let timed_out: Error = CoreError::Nickel {
        source: Box::new(CoreError::ProcessTimeout {
            program: "nickel".into(),
            timeout: Duration::from_secs(1),
        }),
    }
    .into();
    assert_eq!(timed_out.exit_code(), 1);
    assert!(matches!(
        ladyshell::config::relative_path("../outside"),
        Err(Error::InvalidConfiguration { .. })
    ));
}
