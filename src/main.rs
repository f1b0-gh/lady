use clap::Parser;
use ladyshell::{environment_lock, nickel};
use ladyshell_cli::cli::{Cli, Command};
use std::io::{Read, Write};
fn main() {
    let mut exit_status = 0;
    let mut raw = std::env::args_os().skip(1);
    // Preserve legacy arguments, including separators and non-UTF-8 paths.
    let result = if raw.next().as_deref() == Some(std::ffi::OsStr::new("artifact")) {
        ladyshell_cli::artifact_cli::run(ladyshell_cli::artifact_cli::ArtifactArgs {
            arguments: raw.collect(),
        })
    } else {
        let cli = Cli::parse();
        match cli.command {
            Command::Deps(args) => {
                ladyshell_cli::deps_cli::run(args).map(|code| exit_status = code)
            }
            Command::Execution(args) => ladyshell_cli::execution_cli::run(args)
                .and_then(|response| response.map_or(Ok(()), print_json)),
            Command::Artifact(args) => ladyshell_cli::artifact_cli::run(args),
            Command::List { json } => ladyshell::instances::list().and_then(|report| {
                if report["complete"] != true {
                    exit_status = 1;
                }
                if json {
                    print_json(report)
                } else {
                    ladyshell::instances::write(&report, &mut std::io::stdout().lock())
                }
            }),
            Command::Manage(args) => {
                ladyshell_cli::management_cli::run(args).map(|code| exit_status = code)
            }
            Command::Destroy(args) => {
                if args.all {
                    ladyshell::destroy::all(&ladyshell::request::DestroyAll {
                        dry_run: args.dry_run,
                        discard_work: args.discard_work,
                    })
                    .and_then(|report| {
                        if report["complete"] != true {
                            exit_status = 1;
                        }
                        print_json(report)
                    })
                } else {
                    args.try_into()
                        .and_then(|request| ladyshell::destroy::run(&request))
                        .and_then(print_json)
                }
            }
            Command::Check(args) => {
                ladyshell::check::run(&args.state).map(|code| exit_status = code)
            }
            Command::Apply(args) => ladyshell::app::apply(&args.into()).and_then(print_json),
            Command::Shell(args) => ladyshell::interactive::run_with_options(
                &args.state,
                ladyshell::interactive::Kind::Shell,
                args.sync,
                args.publication().as_ref(),
            )
            .and_then(|outcome| session_completion(&args.state, args.cleanup, outcome))
            .map(|code| exit_status = code),
            Command::Chat(args) => ladyshell::interactive::run_with_options(
                &args.state,
                ladyshell::interactive::Kind::Chat,
                args.sync,
                args.publication().as_ref(),
            )
            .and_then(|outcome| session_completion(&args.state, args.cleanup, outcome))
            .map(|code| exit_status = code),
            Command::Resume(args) => ladyshell::interactive::run_with_options(
                &args.state,
                ladyshell::interactive::Kind::Resume,
                args.sync,
                args.publication().as_ref(),
            )
            .and_then(|outcome| session_completion(&args.state, args.cleanup, outcome))
            .map(|code| exit_status = code),
            Command::Publication(args) => publication(args).and_then(print_json),
            Command::Task(args) => task(args).and_then(print_json),
            Command::Review(args) => review(args).and_then(print_json),
            Command::Stack(args) => stack(args).and_then(print_json),
            Command::Cs(args) => continuous(args).and_then(print_json),
            Command::CsWorker => continuous_worker().and_then(print_json),
            Command::CsWorkerProfile => print_json(ladyshell::continuous::worker::profile(
                std::path::Path::new("/sandbox/workspace/project"),
            )),
            Command::Run(args) => ladyshell::run::execute(
                &args.session.state,
                &args.command,
                args.session.sync,
                args.timeout,
                args.session.publication().as_ref(),
            )
            .and_then(|outcome| {
                session_completion(&args.session.state, args.session.cleanup, outcome)
            })
            .map(|code| exit_status = code),
            Command::RemoteAuth => ladyshell::auth::remote_prepare(),
            Command::AuditWorker => audit_worker().and_then(print_json),
            Command::AuditAgent {
                codex,
                cpu_seconds,
                processes,
                file_bytes,
            } => ladyshell::audit::agent::remote(&codex, cpu_seconds, processes, file_bytes),
            Command::Audit(args) => ladyshell::audit::dispatch(args.into()).and_then(|value| {
                let blocked = value["blocked"] == true;
                print_json(value)?;
                if blocked {
                    Err(ladyshell::error::Error::InvalidInput {
                        message: "Audit blocked; inspect blockers".into(),
                    })
                } else {
                    Ok(())
                }
            }),
            Command::Lock(args) => lock(args.into()),
            Command::Plan(args) => ladyshell::app::make_plan(&args.into()).and_then(|plan| {
                writeln!(
                    std::io::stdout().lock(),
                    "{}",
                    serde_json::to_string_pretty(&plan)?
                )?;
                if plan["blocked"] == true {
                    Err(ladyshell::error::Error::InvalidInput {
                        message: "Plan blocked; inspect actions and dependency_scan".into(),
                    })
                } else {
                    Ok(())
                }
            }),
            Command::Status(args) => ladyshell::app::status(&args.state).and_then(|state| {
                writeln!(
                    std::io::stdout().lock(),
                    "{}",
                    serde_json::to_string_pretty(&state)?
                )?;
                Ok(())
            }),
            Command::Sync(args) => {
                let args: ladyshell_cli::cli::SyncArgs = args.into();
                ladyshell::app::sync(&args).and_then(|result| {
                    if args.json {
                        print_json(result)
                    } else {
                        ladyshell::presentation::sync(&result, &mut std::io::stdout().lock())
                    }
                })
            }
            Command::SnapshotList(args) => ladyshell::snapshot::inventory_filtered(
                std::path::Path::new("/sandbox/workspace/project"),
                &args.exclude,
            )
            .and_then(|value| Ok(serde_json::to_value(value)?))
            .and_then(print_json),
            Command::SnapshotPreview(args) => ladyshell::snapshot::preview_filtered(
                std::path::Path::new("/sandbox/workspace/project"),
                &args.exclude,
            )
            .and_then(|value| Ok(serde_json::to_value(value)?))
            .and_then(print_json),
            Command::SnapshotFile(args) => worker_file(args).and_then(print_json),
        }
    };
    if let Err(error) = result {
        let _ = writeln!(std::io::stderr().lock(), "Error: {error}");
        if let ladyshell::error::Error::AuditDocument(
            ladyshell::audit::validator::Error::Validation(messages),
        ) = &error
        {
            for message in messages {
                let _ = writeln!(std::io::stderr().lock(), "  {message}");
            }
        }
        std::process::exit(ladyshell::error::exit_code(&error));
    }
    std::process::exit(exit_status);
}
fn continuous(
    args: ladyshell_cli::cli::ContinuousOptions,
) -> ladyshell::error::Result<serde_json::Value> {
    use ladyshell::continuous::{host, native};
    use ladyshell_cli::cli::ContinuousAction;
    match args.action {
        ContinuousAction::Init { state, task } => native::initialize(&state, &task),
        ContinuousAction::Status(args) => native::status(&args.state),
        ContinuousAction::Checkpoint {
            state,
            attempt,
            epoch,
        } => host::checkpoint_with(&state, &mut native::Native, &attempt, epoch),
        ContinuousAction::ReconcileCheckpoint {
            state,
            before_tree,
            after_tree,
        } => {
            host::reconcile_checkpoint_with(&state, &mut native::Native, &before_tree, &after_tree)
        }
        ContinuousAction::Refresh {
            desired,
            attempt,
            context,
        } => {
            let context =
                ladyshell::json::parse(&ladyshell::files::read_limited(&context, 256 * 1024)?)?;
            native::refresh(&desired.into(), &attempt, &context)
        }
        ContinuousAction::Resume { state, epoch } => {
            host::resume_with(&state, &mut native::Native, epoch)
        }
        ContinuousAction::Replace(args) => native::replace(&args.state),
    }
}
fn continuous_worker() -> ladyshell::error::Result<serde_json::Value> {
    use ladyshell::continuous::worker;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(worker::BUNDLE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    let result = worker::apply(
        std::path::Path::new("/sandbox/workspace/project"),
        std::path::Path::new("/sandbox/workspace/.ladyshell-cs"),
        &bytes,
    )?;
    Ok(serde_json::to_value(result)?)
}
fn lock(args: ladyshell_cli::cli::Desired) -> ladyshell::error::Result<()> {
    let evaluated = nickel::evaluate(&args.config, &args.mission, &args.resources)?;
    let mut receipt = environment_lock::create(
        evaluated.clone(),
        &args.resources,
        &args.codex,
        &args.codex_code_mode_host,
    )?;
    if args.ladybom.is_some() {
        let snapshot =
            ladyshell::sources::snapshot(&args.project, &evaluated.config.sources, None)?;
        let (_, digest) = ladyshell::deps::input::verified_report(
            &args.project,
            &evaluated.config.sources,
            &snapshot,
            args.ladybom.as_deref(),
        )?;
        receipt.ladybom_sha256 = digest;
    }
    let path = args.lock.unwrap_or_else(|| {
        args.config
            .with_extension(format!("{}.lock.json", args.mission))
    });
    environment_lock::write(&path, &receipt)?;
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::json!({"lock":path,"mission":args.mission})
    )?;
    Ok(())
}

fn print_json(value: serde_json::Value) -> ladyshell::error::Result<()> {
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string(&value)?
    )?;
    Ok(())
}

fn audit_worker() -> ladyshell::error::Result<serde_json::Value> {
    const INPUT_LIMIT: usize = 16 * 1024 * 1024;
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(INPUT_LIMIT as u64 + 1)
        .read_to_end(&mut input)?;
    if input.len() > INPUT_LIMIT {
        return Err(ladyshell::error::Error::InvalidInput {
            message: "Audit worker request exceeds 16 MiB".into(),
        });
    }
    let request: ladyshell::audit::worker::WorkerRequest =
        serde_json::from_value(ladyshell::json::parse(&input)?)?;
    Ok(serde_json::to_value(ladyshell::audit::worker::execute(
        request,
    )?)?)
}
fn worker_file(
    args: ladyshell_cli::cli::WorkerFile,
) -> ladyshell::error::Result<serde_json::Value> {
    for excluded in &args.filters.exclude {
        ladyshell::config::relative_path(excluded)?;
    }
    let spec = ladyshell::config::Sources {
        include: vec![],
        exclude: args.filters.exclude,
    };
    if ladyshell::sources::excluded(&args.path, &spec) {
        return Err(ladyshell::error::Error::InvalidInput {
            message: "Chemin exclu".into(),
        });
    }
    Ok(serde_json::to_value(ladyshell::snapshot::read_file(
        std::path::Path::new("/sandbox/workspace/project"),
        &args.path,
    )?)?)
}

fn completion(outcome: ladyshell::run::Outcome) -> ladyshell::error::Result<i32> {
    if let Some(report) = outcome.sync {
        let mut output = std::io::stderr().lock();
        if outcome.exit_code != 0 {
            writeln!(
                output,
                "Command exited {}; changes were exported without applying them.",
                outcome.exit_code
            )?;
        }
        writeln!(output, "Sync: {}", serde_json::to_string(&report)?)?;
    }
    Ok(outcome.exit_code)
}

fn session_completion(
    state: &std::path::Path,
    cleanup: bool,
    outcome: ladyshell::run::Outcome,
) -> ladyshell::error::Result<i32> {
    let mut code = completion(outcome)?;
    if cleanup {
        match ladyshell::tasks::complete(state) {
            Ok(receipt) => print_json(serde_json::json!({"cleanup":receipt}))?,
            Err(e) => {
                print_json(
                    serde_json::json!({"cleanup_confirmed":false,"error":e.to_string(),"state":state}),
                )?;
                if code == 0 {
                    code = 1;
                }
            }
        }
    }
    Ok(code)
}
fn publication(
    args: ladyshell_cli::cli::PublicationOptions,
) -> ladyshell::error::Result<serde_json::Value> {
    use ladyshell_cli::cli::PublicationAction;
    match args.action {
        PublicationAction::Publish {
            state,
            export,
            remote,
            branch,
            message,
            policy,
        } => ladyshell::retained_publication::run(
            &state,
            &export,
            &ladyshell::publish::Options {
                remote,
                branch,
                message,
                policy,
            },
        ),
        PublicationAction::Check {
            state,
            export,
            policy,
        } => ladyshell::publication_checks::retained(&state, &export, &policy),
        PublicationAction::Status(args) => ladyshell::publication_recovery::status(&args.state),
        PublicationAction::Reconcile {
            state,
            retry,
            abandon,
        } => ladyshell::publication_recovery::reconcile(&state, retry, abandon),
    }
}
fn task(args: ladyshell_cli::cli::TaskOptions) -> ladyshell::error::Result<serde_json::Value> {
    use ladyshell_cli::cli::TaskAction;
    match args.action {
        TaskAction::Prepare {
            repository,
            directory,
            branch,
            base,
        } => ladyshell::tasks::prepare(&repository, &directory, &branch, &base),
        TaskAction::Start(a) => {
            let desired = ladyshell::request::Desired {
                project: a.repository,
                state: a.directory.join("state"),
                config: a.config,
                resources: a.resources,
                codex: a.codex,
                codex_code_mode_host: a.codex_code_mode_host,
                lock: a.lock,
                ladybom: a.ladybom,
                mission: a.mission,
            };
            ladyshell::tasks::start(desired, &a.directory, &a.branch, &a.base)
        }
        TaskAction::Status(a) => ladyshell::tasks::status(&a.state),
        TaskAction::Inspect {
            state,
            export,
            live,
        } => {
            if live {
                ladyshell::tasks::inspect_live(&state)
            } else {
                ladyshell::tasks::inspect(&state, export.as_deref())
            }
        }
        TaskAction::Salvage { state, export } => ladyshell::tasks::salvage(&state, &export),
        TaskAction::Refresh { state, upstream } => ladyshell::tasks::refresh(&state, &upstream),
        TaskAction::Complete(a) => ladyshell::tasks::complete(&a.state),
    }
}

fn review(args: ladyshell_cli::cli::ReviewOptions) -> ladyshell::error::Result<serde_json::Value> {
    use ladyshell_cli::cli::ReviewAction;
    match args.action {
        ReviewAction::Handoff {
            existing,
            from_state,
            from_attempt,
            head,
            base,
            policy,
        } => ladyshell::tangled_review::handoff(
            &existing.state,
            &existing.config,
            &ladyshell::tangled_review::HandoffInput {
                from_state,
                from_attempt,
                head,
                base,
                policy,
            },
        ),
        ReviewAction::Submit {
            existing,
            ticket,
            created_at,
            target_base,
            target_branch,
            title,
            body,
            resubmit,
        } => ladyshell::tangled_review::submit(
            &existing.state,
            &existing.config,
            &ladyshell::tangled_review::SubmitInput {
                ticket_key: ticket.unwrap_or_default(),
                created_at,
                target_base,
                target_branch,
                title,
                body,
                resubmit,
            },
        ),
        ReviewAction::OwnerDecision {
            existing,
            decision,
            head,
            base,
            patch_uri,
            patch_cid,
            explanation,
        } => {
            let decision = serde_json::from_value(serde_json::json!(decision))?;
            ladyshell::tangled_review::record_owner_decision(
                &existing.state,
                &existing.config,
                &ladyshell::tangled_review::DecisionInput {
                    decision,
                    head,
                    base,
                    patch_uri,
                    patch_cid,
                    explanation,
                },
            )
        }
        ReviewAction::Status(a) => ladyshell::tangled_review::status(&a.state, &a.config),
        ReviewAction::Feedback { existing, deliver } => {
            let mut result =
                ladyshell::tangled_review::feedback(&existing.state, &existing.config)?;
            if deliver {
                result["delivery"] = ladyshell::tangled_review::deliver_feedback(&existing.state)?;
            }
            Ok(result)
        }
        ReviewAction::Reconcile(a) => ladyshell::tangled_review::reconcile(&a.state, &a.config),
        ReviewAction::SelectTicket {
            existing,
            ticket_uri,
            ticket_cid,
        } => ladyshell::tangled_review::select_ticket(
            &existing.state,
            &existing.config,
            &ticket_uri,
            &ticket_cid,
        ),
        ReviewAction::AbandonTicket {
            existing,
            explanation,
        } => ladyshell::tangled_review::abandon_ticket(
            &existing.state,
            &existing.config,
            &explanation,
        ),
        ReviewAction::RebindCredentials(a) => {
            ladyshell::tangled_review::rebind_credentials(&a.state, &a.config)
        }
        ReviewAction::Merge {
            existing,
            policy,
            remote,
            branch,
            head,
            expected_target,
        } => ladyshell::review_merge::run(
            &existing.state,
            &ladyshell::review_merge::Options {
                config: &existing.config,
                policy: &policy,
                remote: &remote,
                branch: &branch,
                head: &head,
                expected: &expected_target,
            },
        ),
        ReviewAction::MergeCheck {
            existing,
            policy,
            remote,
            branch,
            head,
            expected_target,
        } => ladyshell::review_merge::check(
            &existing.state,
            &ladyshell::review_merge::Options {
                config: &existing.config,
                policy: &policy,
                remote: &remote,
                branch: &branch,
                head: &head,
                expected: &expected_target,
            },
        ),
        ReviewAction::MergeReconcile { state, retry } => {
            ladyshell::review_merge::reconcile(&state, retry)
        }
    }
}

fn stack(args: ladyshell_cli::cli::StackOptions) -> ladyshell::error::Result<serde_json::Value> {
    use ladyshell_cli::cli::StackAction;
    match args.action {
        StackAction::Record {
            directory,
            state,
            parent,
        } => ladyshell::stacks::record(&directory, &state, parent.as_deref()),
        StackAction::Status { directory } => ladyshell::stacks::status(&directory),
        StackAction::Restack {
            directory,
            state,
            onto,
        } => ladyshell::stacks::restack_onto(&directory, &state, onto.as_deref()),
    }
}
