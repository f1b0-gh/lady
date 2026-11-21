#![allow(clippy::unwrap_used)] // Synthetic HTTP fixture internals only.
use ladyshell::tangled_review::{self, SubmitInput};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
const TICKET_CID: &str = "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_TICKET_CID: &str = "bafyreiabaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibae";
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    root: tempfile::TempDir,
    url: String,
    data: Arc<Mutex<Value>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(lost: bool) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let data = Arc::new(Mutex::new(
            json!({"ticket":null,"patches":[],"writes":0,"lost":lost,"ticket_cid":TICKET_CID}),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let d = data.clone();
        let s = stop.clone();
        let worker = thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let Ok((mut socket, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
                let mut bytes = Vec::new();
                let mut block = [0; 4096];
                let mut end = None;
                loop {
                    match socket.read(&mut block) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => bytes.extend_from_slice(&block[..n]),
                    }
                    if let Some(pos) = bytes.windows(4).position(|x| x == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..pos]);
                        let length = headers
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= pos + 4 + length {
                            end = Some(pos + 4);
                            break;
                        }
                    }
                }
                let Some(end) = end else { continue };
                let request = String::from_utf8_lossy(&bytes[..end]);
                let route = request.lines().next().unwrap_or("");
                let mut state = match d.lock() {
                    Ok(d) => d,
                    Err(_) => return,
                };
                state["requests"] = json!(state["requests"].as_u64().unwrap_or(0) + 1);
                let body: Value = serde_json::from_slice(&bytes[end..]).unwrap_or(Value::Null);
                let response = if route.contains("createRecord") {
                    if body.get("rkey").is_some() {
                        let _ = write!(socket,"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        continue;
                    }
                    state["writes"] = json!(state["writes"].as_u64().unwrap_or(0) + 1);
                    state["ticket"] = body["record"].clone();
                    state["ticket"]["x-tngl-editor"] = json!("did:plc:actor");
                    state["ticket"]["createdAt"] = json!("2026-11-05T12:34:56.125Z");
                    state["ticket"]["serverExtension"] = json!("SECRET_PROVIDER_FIELD");
                    if state["ticket_lost"] == true {
                        state["ticket_lost"] = json!(false);
                        continue;
                    }
                    json!({"uri":"at://did:plc:repo/org.tangled.track.ticket/79","cid":state["ticket_cid"],"x-tngl-change":"1111111111111111111111111111111111111111","serverExtension":"SECRET_PROVIDER_FIELD"})
                } else if route.contains("submitPatch") {
                    if state["reject_patch"] == true {
                        let _=write!(socket,"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSECRET");
                        continue;
                    }
                    state["writes"] = json!(state["writes"].as_u64().unwrap_or(0) + 1);
                    let p = &body["patch"];
                    let index = state["patches"].as_array().unwrap().len() + 1;
                    let uri = format!("at://did:plc:repo/org.tangled.review.patch/round{index}");
                    let cid = if index == 1 {
                        "roundcid".to_string()
                    } else {
                        format!("roundcid{index}")
                    };
                    let record = json!({"uri":uri,"cid":cid,"value":{"$type":"org.tangled.review.patch","ticket":p["ticket"],"base":p["base"],"head":p["head"],"source":{"repo":p["sourceRepo"],"branch":p["sourceBranch"]},"createdAt":format!("2026-11-05T00:00:{index:02}Z")}});
                    state["patches"].as_array_mut().unwrap().push(record);
                    if state["lost"] == true {
                        state["lost"] = json!(false);
                        continue;
                    }
                    json!({"uri":uri,"cid":cid,"x-tngl-change":"2222222222222222222222222222222222222222"})
                } else if route.contains("getRecord") {
                    let mut record = json!({"uri":"at://did:plc:repo/org.tangled.track.ticket/79","cid":state["ticket_cid"],"value":state["ticket"]});
                    if let Some(cid) = state.get("readback_cid") {
                        record["cid"] = cid.clone();
                    }
                    if let Some(extras) = state["extra_tickets"].as_array() {
                        for extra in extras {
                            if extra["uri"].as_str().is_some_and(|u| {
                                route.contains(&format!("rkey={}", u.rsplit('/').next().unwrap()))
                            }) {
                                record = extra.clone();
                            }
                        }
                    }
                    record
                } else if route.contains("listRecords") {
                    if route.contains("org.tangled.track.ticket") {
                        let mut records = if state["ticket"].is_null() {
                            vec![]
                        } else {
                            vec![
                                json!({"uri":"at://did:plc:repo/org.tangled.track.ticket/79","cid":state["ticket_cid"],"value":state["ticket"]}),
                            ]
                        };
                        if let Some(extra) = state["extra_tickets"].as_array() {
                            records.extend(extra.iter().cloned());
                        }
                        json!({"records":records,"cursor":state["ticket_cursor"]})
                    } else {
                        json!({"records":state["patches"]})
                    }
                } else if route.contains("queryPipelines") {
                    if state["ci_unavailable"] == true {
                        let _ = write!(socket, "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        continue;
                    }
                    if !state["ci"].is_null() {
                        state["ci"].clone()
                    } else {
                        json!({"total":1,"pipelines":[{"repo":"did:plc:repo","commit":"ffffffffffffffffffffffffffffffffffffffff","workflows":[{"status":"success"}]}]})
                    }
                } else if route.contains("listComments") {
                    json!({"items":[{"uri":"at://did:plc:user/org.tangled.feed.comment/c","subject":{"uri":"at://did:plc:repo/org.tangled.review.patch/round1","cid":"roundcid"},"body":{"text":"Please revise"}}]})
                } else {
                    json!({})
                };
                let output = response.to_string();
                let _ = write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    output.len(),
                    output
                );
            }
        });
        let f = Self {
            root,
            url,
            data,
            stop,
            worker: Some(worker),
        };
        f.setup()?;
        Ok(f)
    }
    fn setup(&self) -> Result {
        fs::create_dir(self.root.path().join("project"))?;
        ladyshell::state::create_directory(&self.root.path().join("state"))?;
        let helper = self.root.path().join("auth");
        fs::write(&helper,"#!/usr/bin/python3\nimport sys,json,base64,time\np={'aud':sys.argv[1],'lxm':sys.argv[2],'exp':int(time.time())+120}\ns=base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip('=')\nprint('e30.'+s+'.signature')\n")?;
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))?;
        fs::write(
            self.config(),
            serde_json::to_vec(
                &json!({"schema_version":1,"knot":self.url,"repository":"did:plc:repo","source_repository":"did:plc:repo","web_url":format!("{}/owner/repo",self.url),"bobbin":self.url,"spindle":self.url,"auth_program":helper}),
            )?,
        )?;
        self.publication("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
        Ok(())
    }
    fn publication(&self, head: &str) -> Result {
        fs::write(
            self.state().join("publication.json"),
            serde_json::to_vec(
                &json!({"schema_version":2,"phase":"published","confirmed":true,"project":self.root.path().join("project"),"destination":format!("{}/did:plc:repo",self.url),"reference":"refs/heads/draft","branch":"draft","base":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","commit":head}),
            )?,
        )?;
        Ok(())
    }
    fn state(&self) -> std::path::PathBuf {
        self.root.path().join("state")
    }
    fn config(&self) -> std::path::PathBuf {
        self.root.path().join("config.json")
    }
    fn input(&self) -> SubmitInput {
        SubmitInput {
            ticket_key: String::new(),
            created_at: "2026-11-05T00:00:00Z".into(),
            target_base: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            target_branch: "main".into(),
            title: "Review".into(),
            body: "Changes".into(),
            resubmit: false,
        }
    }
}
#[test]
fn continuous_review_refuses_old_epoch_and_pending_handoff_before_provider() -> Result {
    use ladyshell::continuous::{
        host,
        model::{Phase, Session},
    };
    let f = Fixture::new(false)?;
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    let export = f.state().join("export");
    fs::create_dir(&export)?;
    let mut publication =
        ladyshell::state::read(&f.state().join("publication.json"))?.ok_or("publication")?;
    publication["export"] = json!(export);
    ladyshell::files::publish_json(&f.state().join("publication.json"), &publication, true)?;
    let mut session = Session::new(
        "task".into(),
        "sandbox".into(),
        "owner".into(),
        "runtime".into(),
        "a".repeat(64),
        "b".repeat(64),
    )?;
    let mut current = json!({"schema_version":2,"sandbox_name":"test","sandbox_id":"sandbox",
        "owner":"owner","policy_hash":"hash","codex_binary":"codex","desired_hash":"desired",
        "image_id":"image","project_snapshot":"snapshot","build_dir":"build",
        "context":{"gateway":"test","workspace":"default"},"continuous":session});
    ladyshell::files::publish_json(
        &export.join("manifest.json"),
        &json!({"continuous":host::export_binding(&current)?}),
        true,
    )?;
    let mut input = f.input();
    input.resubmit = true;
    for pending in [false, true] {
        session.epoch = if pending { 0 } else { 1 };
        session.phase = if pending {
            Phase::Checkpointed
        } else {
            Phase::Ready
        };
        current["continuous"] = serde_json::to_value(&session)?;
        ladyshell::files::publish_json(&f.state().join("state.json"), &current, true)?;
        let before = f.data.lock().map_err(|_| "fixture lock")?["requests"].clone();
        let expected = if pending {
            "handoff is pending"
        } else {
            "another continuous epoch"
        };
        let error = tangled_review::submit(&f.state(), &f.config(), &input)
            .err()
            .ok_or("stale submit admitted")?;
        assert!(error.to_string().contains(expected), "{error}");
        let error = tangled_review::merge_admission(
            &f.state(),
            &f.config(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .err()
        .ok_or("stale merge admitted")?;
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(
            f.data.lock().map_err(|_| "fixture lock")?["requests"],
            before
        );
        let status = tangled_review::status(&f.state(), &f.config())?;
        assert_eq!(status["source_ahead"], true);
        assert_eq!(status["continuous_publication_current"], false);
    }
    Ok(())
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
#[test]
fn submit_readback_status_feedback_exact_bindings() -> Result {
    let f = Fixture::new(false)?;
    let receipt = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert_eq!(receipt["phase"], "submitted");
    assert_eq!(
        receipt["submitted_head"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let status = tangled_review::status(&f.state(), &f.config())?;
    assert_eq!(status["source_ahead"], false);
    assert_eq!(status["ci"]["status"], "unknown");
    let feedback = tangled_review::feedback(&f.state(), &f.config())?;
    assert_eq!(feedback["patch"]["cid"], "roundcid");
    assert!(f.state().join("review-feedback.json").exists());
    f.publication("cccccccccccccccccccccccccccccccccccccccc")?;
    let status = tangled_review::status(&f.state(), &f.config())?;
    assert_eq!(status["source_ahead"], true);
    assert!(tangled_review::merge_admission(
        &f.state(),
        &f.config(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    .is_err());
    Ok(())
}
#[test]
fn lost_patch_response_reconciles_without_duplicate() -> Result {
    let f = Fixture::new(true)?;
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let receipt = tangled_review::reconcile(&f.state(), &f.config())?;
    assert_eq!(receipt["phase"], "submitted");
    let receipt = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert_eq!(receipt["phase"], "submitted");
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}
#[test]
fn rejects_project_config_and_expired_auth_before_write() -> Result {
    let f = Fixture::new(false)?;
    let inside = f.root.path().join("project/config.json");
    fs::copy(f.config(), &inside)?;
    assert!(tangled_review::submit(&f.state(), &inside, &f.input()).is_err());
    let helper = f.root.path().join("auth");
    fs::write(&helper,"#!/bin/sh\nprintf 'e30.eyJhdWQiOiJkaWQ6cGxjOnJlcG8iLCJseG0iOiJjb20uYXRwcm90by5yZXBvLmNyZWF0ZVJlY29yZCIsImV4cCI6MX0.signature'\n")?;
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 0);
    Ok(())
}

#[test]
fn wrong_audience_and_secret_helper_failure_are_redacted_and_recoverable() -> Result {
    let f = Fixture::new(false)?;
    let helper = f.root.path().join("auth");
    let original = fs::read_to_string(&helper)?;
    fs::write(&helper, original.replace("sys.argv[1]", "'did:plc:wrong'"))?;
    let error = tangled_review::submit(&f.state(), &f.config(), &f.input())
        .err()
        .ok_or("wrong audience accepted")?;
    assert!(error.to_string().contains("audience"));
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 0);
    fs::write(&helper, "#!/bin/sh\nprintf SECRET_AUTH_TOKEN >&2\nexit 1\n")?;
    let error = tangled_review::reconcile(&f.state(), &f.config())
        .err()
        .ok_or("failed helper accepted")?;
    assert!(!error.to_string().contains("SECRET_AUTH_TOKEN"));
    fs::write(&helper, original)?;
    assert_eq!(
        tangled_review::reconcile(&f.state(), &f.config())?["phase"],
        "submitted"
    );
    Ok(())
}
#[test]
fn accepted_lost_ticket_is_read_back_before_patch() -> Result {
    let f = Fixture::new(false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    assert_eq!(select_and_reconcile(&f)?["phase"], "submitted");
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}
#[test]
fn resubmit_is_explicit_immutable_and_stale_round_is_refused() -> Result {
    let f = Fixture::new(false)?;
    let first = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    f.publication("cccccccccccccccccccccccccccccccccccccccc")?;
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let mut input = f.input();
    input.resubmit = true;
    input.ticket_key = "79".into();
    let second = tangled_review::submit(&f.state(), &f.config(), &input)?;
    assert_ne!(first["patch"]["uri"], second["patch"]["uri"]);
    assert!(f
        .state()
        .join("review-attempts")
        .join(first["attempt"].as_str().ok_or("attempt")?)
        .join("confirmed.json")
        .exists());
    let status = tangled_review::status(&f.state(), &f.config())?;
    assert_eq!(status["superseded"], false);
    {
        let mut d = f.data.lock().map_err(|e| e.to_string())?;
        let mut newer = d["patches"][1].clone();
        newer["uri"] = json!("at://did:plc:repo/org.tangled.review.patch/round3");
        newer["cid"] = json!("roundcid3");
        newer["value"]["createdAt"] = json!("2026-11-05T00:00:03Z");
        d["patches"].as_array_mut().ok_or("patches")?.push(newer);
    }
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["superseded"],
        true
    );
    assert!(tangled_review::merge_admission(
        &f.state(),
        &f.config(),
        "cccccccccccccccccccccccccccccccccccccccc",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    .is_err());
    Ok(())
}
#[test]
fn empty_workflow_and_missing_remote_round_never_admit_merge() -> Result {
    let f = Fixture::new(false)?;
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    {
        let mut d = f.data.lock().map_err(|e| e.to_string())?;
        d["ci"] = json!({"total":1,"pipelines":[{"repo":"did:plc:repo","commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workflows":[]}]});
    }
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["ci"]["status"],
        "unknown"
    );
    f.data.lock().map_err(|e| e.to_string())?["patches"] = json!([]);
    assert!(tangled_review::merge_admission(
        &f.state(),
        &f.config(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )
    .is_err());
    Ok(())
}
#[test]
fn absent_uncertain_patch_and_wrong_source_never_duplicate() -> Result {
    let f = Fixture::new(true)?;
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    {
        let mut d = f.data.lock().map_err(|e| e.to_string())?;
        d["patches"][0]["value"]["source"]["repo"] = json!("did:plc:other");
    }
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}

#[test]
fn http_refusal_retains_intent_and_suppresses_response() -> Result {
    let f = Fixture::new(false)?;
    f.data.lock().map_err(|e| e.to_string())?["reject_patch"] = json!(true);
    let error = tangled_review::submit(&f.state(), &f.config(), &f.input())
        .err()
        .ok_or("HTTP403 accepted")?;
    assert!(!error.to_string().contains("SECRET"));
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    Ok(())
}
#[test]
fn refuses_changed_source_and_stale_recovery_before_new_effect() -> Result {
    let f = Fixture::new(false)?;
    let mut publication: Value =
        serde_json::from_slice(&fs::read(f.state().join("publication.json"))?)?;
    publication["destination"] = json!("https://other.invalid/unrelated");
    fs::write(
        f.state().join("publication.json"),
        serde_json::to_vec(&publication)?,
    )?;
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 0);
    f.publication("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    f.publication("cccccccccccccccccccccccccccccccccccccccc")?;
    let pending = tangled_review::reconcile(&f.state(), &f.config())?;
    assert_eq!(pending["phase"], "ticket_pending");
    tangled_review::select_ticket(
        &f.state(),
        &f.config(),
        "at://did:plc:repo/org.tangled.track.ticket/79",
        TICKET_CID,
    )?;
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    Ok(())
}
#[test]
fn fractional_second_newer_round_is_superseded() -> Result {
    let f = Fixture::new(false)?;
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    {
        let mut d = f.data.lock().map_err(|e| e.to_string())?;
        let mut newer = d["patches"][0].clone();
        newer["uri"] = json!("at://did:plc:repo/org.tangled.review.patch/fractional");
        newer["cid"] = json!("fractionalcid");
        newer["value"]["createdAt"] = json!("2026-11-05T00:00:01.5Z");
        d["patches"].as_array_mut().ok_or("patches")?.push(newer);
    }
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["superseded"],
        true
    );
    Ok(())
}
#[test]
fn closed_or_retargeted_ticket_cannot_authorize_merge() -> Result {
    let f = Fixture::new(false)?;
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert!(tangled_review::merge_admission(
        &f.state(),
        &f.config(),
        &"a".repeat(40),
        &"b".repeat(40)
    )
    .is_ok());
    f.data.lock().map_err(|e| e.to_string())?["ticket"]["state"] = json!("completed");
    assert!(tangled_review::merge_admission(
        &f.state(),
        &f.config(),
        &"a".repeat(40),
        &"b".repeat(40)
    )
    .is_err());
    {
        let mut d = f.data.lock().map_err(|e| e.to_string())?;
        d["ticket"]["state"] = json!("open");
        d["ticket"]["targetBranch"] = json!("release");
    }
    assert!(tangled_review::merge_admission(
        &f.state(),
        &f.config(),
        &"a".repeat(40),
        &"b".repeat(40)
    )
    .is_err());
    Ok(())
}
#[test]
fn merge_target_branch_is_bound_before_host_signing_or_push() -> Result {
    let f = Fixture::new(false)?;
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    let error = ladyshell::review_merge::run(
        &f.state(),
        &ladyshell::review_merge::Options {
            config: &f.config(),
            policy: &f.root.path().join("not-selected"),
            remote: "knot",
            branch: "release",
            head: &"a".repeat(40),
            expected: &"b".repeat(40),
        },
    )
    .err()
    .ok_or("unbound merge admitted")?;
    assert!(error.to_string().contains("reviewed target branch"));
    assert!(!f.state().join("merge.json").exists());
    Ok(())
}
#[test]
fn merge_retry_rechecks_closed_review_before_any_git_push() -> Result {
    use std::process::Command;
    let f = Fixture::new(false)?;
    let project = f.root.path().join("project");
    let remote = f.root.path().join("remote.git");
    fs::create_dir(&remote)?;
    let git = |root: &std::path::Path, args: &[&str]| -> Result<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()?;
        if !out.status.success() {
            return Err(String::from_utf8(out.stderr)?.into());
        }
        Ok(String::from_utf8(out.stdout)?.trim().into())
    };
    git(&project, &["init", "-b", "draft"])?;
    git(&remote, &["init", "--bare"])?;
    git(&project, &["config", "user.name", "Fixture"])?;
    git(
        &project,
        &["config", "user.email", "fixture@example.invalid"],
    )?;
    fs::write(project.join("code"), "base")?;
    git(&project, &["add", "code"])?;
    git(&project, &["commit", "-m", "base"])?;
    let base = git(&project, &["rev-parse", "HEAD"])?;
    git(
        &project,
        &[
            "push",
            remote.to_str().ok_or("remote")?,
            "HEAD:refs/heads/main",
        ],
    )?;
    fs::write(project.join("code"), "candidate")?;
    git(&project, &["commit", "-am", "candidate"])?;
    let head = git(&project, &["rev-parse", "HEAD"])?;
    f.publication(&head)?;
    let mut input = f.input();
    input.target_base = base.clone();
    let review = tangled_review::submit(&f.state(), &f.config(), &input)?;
    let intent = json!({"schema_version":1,"project":project,"destination":remote,"reference":"refs/heads/main","expected_target":base,"head":head,"confirmed":false,"review_config":f.config(),"review":{"review":review}});
    fs::write(f.state().join("merge.json"), serde_json::to_vec(&intent)?)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket"]["state"] = json!("completed");
    let error = ladyshell::review_merge::reconcile(&f.state(), true)
        .err()
        .ok_or("closed review retried")?;
    assert!(error.to_string().contains("closed"));
    assert_eq!(git(&remote, &["rev-parse", "main"])?, base);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(f.state().join("merge.json"))?)?,
        intent
    );
    Ok(())
}

fn typed_connector(f: &Fixture, lost: bool) -> Result {
    let helper = f.root.path().join("connector");
    fs::write(
        &helper,
        r#"#!/usr/bin/python3
import sys,json,urllib.request,pathlib
c=json.loads(pathlib.Path(sys.argv[-1]).read_text())
p=pathlib.Path(c['fixture_state']);s=json.loads(p.read_text()) if p.exists() else {'attestations':{},'writes':0,'lost':False}
if sys.argv[1]=='account':
 a=dict(schema_version=1,mode='trusted_owner',account=s.get('account_override',c['account']),connection=c['connection'],generation=c['generation'],knot=c['knot'],repository=c['repository'],source_repository=c['source_repository'],profile='TangledReview',available=s.get('available',True),lease_expired=not s.get('available',True),uncertain_refresh=False)
 if c['schema_version']==2:
  a.pop('lease_expired');a.update(schema_version=2,session_policy='refreshable',lifecycle='active',access_expires_at=1800000300,access_expired=False)
 a.update(s.get('observation_overrides',{}))
 print(json.dumps(a))
 sys.exit(0)
q=json.load(sys.stdin)
assert q['generation']==c['generation'] and q['connection']==c['connection']
s.setdefault('calls',[]).append({'action':sys.argv[1],'request':q});p.write_text(json.dumps(s))
operation=q['operation'];outcome='confirmed'
if s.get('blocked_operation')==operation and sys.argv[1]=='execute':
 print(json.dumps({'schema_version':1,'mode':'trusted_owner','account':c['account'],'knot':c['knot'],'repository':c['repository'],'source_repository':c['source_repository'],'outcome':'not_sent','connection':q['connection'],'generation':q['generation'],'request_id':q['request_id'],'result':None}))
 sys.exit(0)
if operation=='attest_record':
 key=q['body']['rkey'];record=q['body']['record']
 if sys.argv[1]=='execute':
  if key not in s['attestations']:s['writes']+=1;s['attestations'][key]=record
  if c['lost'] and not s['lost']:s['lost']=True;outcome='unknown'
 else:
  assert s['attestations'][key]==record
 result={'uri':'at://'+c['account']+'/org.tangled.graph.attestation/'+key,'cid':'attestcid'+key}
else:
 nsid={'create_ticket':'com.atproto.repo.createRecord','submit_patch':'org.tangled.review.submitPatch'}[operation]
 request=urllib.request.Request(c['knot']+'/xrpc/'+nsid,data=json.dumps(q['body']).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(request) as r:result=json.load(r)
p.write_text(json.dumps(s))
print(json.dumps({'schema_version':1,'mode':'trusted_owner','account':c['account'],'knot':c['knot'],'repository':c['repository'],'source_repository':c['source_repository'],'outcome':outcome,'connection':q['connection'],'generation':q['generation'],'request_id':q['request_id'],'result':result}))
"#,
    )?;
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))?;
    let host = f.root.path().join("host.json");
    fs::write(
        &host,
        serde_json::to_vec(
            &json!({"schema_version":1,"mode":"trusted_owner","account":"did:plc:actor","connection":1,"generation":1,"knot":f.url,"repository":"did:plc:repo","source_repository":"did:plc:repo","fixture_state":f.root.path().join("connector-state.json"),"lost":lost}),
        )?,
    )?;
    let mut c: Value = serde_json::from_slice(&fs::read(f.config())?)?;
    c["schema_version"] = json!(2);
    c.as_object_mut().ok_or("config")?.remove("auth_program");
    c["connector"] = json!({"program":helper,"config":host,"account":"did:plc:actor","connection":1,"generation":1});
    fs::write(f.config(), serde_json::to_vec(&c)?)?;
    Ok(())
}
#[test]
fn typed_host_attests_ticket_and_patch_without_exporting_credentials() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    let first = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert_eq!(first["phase"], "submitted");
    assert_eq!(first["knot_confirmed"], true);
    assert_eq!(
        first["attestations"]
            .as_array()
            .ok_or("attestations")?
            .len(),
        2
    );
    assert!(first["attestations"]
        .as_array()
        .ok_or("attestations")?
        .iter()
        .all(|a| a["phase"] == "confirmed"));
    let stored: Value =
        serde_json::from_slice(&fs::read(f.root.path().join("connector-state.json"))?)?;
    assert_eq!(stored["writes"], 2);
    f.publication("cccccccccccccccccccccccccccccccccccccccc")?;
    let mut next = f.input();
    next.resubmit = true;
    next.ticket_key = "79".into();
    let second = tangled_review::submit(&f.state(), &f.config(), &next)?;
    assert_eq!(
        second["attestations"]
            .as_array()
            .ok_or("attestations")?
            .len(),
        1
    );
    assert_ne!(first["patch"], second["patch"]);
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 3);
    Ok(())
}
#[test]
fn lost_actor_attestation_reconciles_exact_key_without_duplicate_patch() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, true)?;
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let pending: Value = serde_json::from_slice(&fs::read(f.state().join("review.json"))?)?;
    assert_eq!(pending["phase"], "attestation_pending");
    assert_eq!(pending["knot_confirmed"], true);
    let r = tangled_review::reconcile(&f.state(), &f.config())?;
    assert_eq!(r["phase"], "submitted");
    assert_eq!(r["patch"], pending["patch"]);
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    let stored: Value =
        serde_json::from_slice(&fs::read(f.root.path().join("connector-state.json"))?)?;
    assert_eq!(stored["writes"], 2);
    Ok(())
}

#[test]
fn typed_response_binding_failure_preserves_unknown_write_for_readback() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    let helper = f.root.path().join("connector");
    let original = fs::read_to_string(&helper)?;
    fs::write(
        &helper,
        original.replace(
            "'generation':q['generation']",
            "'generation':q['generation']+1",
        ),
    )?;
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let pending: Value = serde_json::from_slice(&fs::read(f.state().join("review.json"))?)?;
    assert_eq!(pending["phase"], "ticket_pending");
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    fs::write(&helper, original)?;
    assert_eq!(select_and_reconcile(&f)?["phase"], "submitted");
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}

#[test]
fn typed_review_retains_public_authority_from_initial_intent() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    let receipt = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert_eq!(receipt["schema_version"], 2);
    assert_eq!(receipt["connector_authority"]["account"], "did:plc:actor");
    assert_eq!(receipt["connector_authority"]["generation"], 1);
    assert_eq!(receipt["credential_history"], json!([]));
    let intent: Value = serde_json::from_slice(&fs::read(
        f.state()
            .join("review-attempts")
            .join(receipt["attempt"].as_str().ok_or("attempt")?)
            .join("intent.json"),
    )?)?;
    assert_eq!(
        intent["connector_authority"],
        receipt["connector_authority"]
    );
    assert!(!receipt.to_string().contains("access_token"));
    Ok(())
}

fn connector_runtime(f: &Fixture) -> Result<Value> {
    let path = f.root.path().join("connector-state.json");
    Ok(if path.exists() {
        serde_json::from_slice(&fs::read(path)?)?
    } else {
        json!({"attestations":{},"writes":0,"lost":false})
    })
}
fn store_connector_runtime(f: &Fixture, value: &Value) -> Result {
    fs::write(
        f.root.path().join("connector-state.json"),
        serde_json::to_vec(value)?,
    )?;
    Ok(())
}
fn advance_credentials(f: &Fixture, generation: u64) -> Result {
    let mut config: Value = serde_json::from_slice(&fs::read(f.config())?)?;
    config["connector"]["generation"] = json!(generation);
    fs::write(f.config(), serde_json::to_vec(&config)?)?;
    let path = f.root.path().join("host.json");
    let mut host: Value = serde_json::from_slice(&fs::read(&path)?)?;
    host["generation"] = json!(generation);
    fs::write(path, serde_json::to_vec(&host)?)?;
    Ok(())
}
fn review_receipt(f: &Fixture) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(
        f.state().join("review.json"),
    )?)?)
}

#[test]
fn credential_rebind_recovers_ready_and_uncertain_stages_without_repeating_effects() -> Result {
    for stage in [
        "ticket_ready",
        "patch_ready",
        "attestation_ready",
        "ticket_pending",
        "patch_pending",
        "attestation_pending",
    ] {
        let f = Fixture::new(stage == "patch_pending")?;
        typed_connector(&f, stage == "attestation_pending")?;
        if stage == "ticket_pending" {
            f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
        }
        let blocked = match stage {
            "ticket_ready" => Some("create_ticket"),
            "patch_ready" => Some("submit_patch"),
            "attestation_ready" => Some("attest_record"),
            _ => None,
        };
        if let Some(operation) = blocked {
            let mut runtime = connector_runtime(&f)?;
            runtime["blocked_operation"] = json!(operation);
            runtime["available"] = json!(false);
            store_connector_runtime(&f, &runtime)?;
        }
        assert!(
            tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err(),
            "{stage}"
        );
        let prior = review_receipt(&f)?;
        assert_eq!(
            prior["phase"],
            if stage == "attestation_ready" {
                "attestation_pending"
            } else {
                stage
            },
            "{stage}"
        );
        let writes = f.data.lock().map_err(|e| e.to_string())?["writes"].clone();
        let actor_writes = connector_runtime(&f)?["writes"].clone();
        advance_credentials(&f, 2)?;
        assert!(
            tangled_review::reconcile(&f.state(), &f.config()).is_err(),
            "generation must not update implicitly: {stage}"
        );
        let mut runtime = connector_runtime(&f)?;
        runtime["blocked_operation"] = Value::Null;
        runtime["available"] = json!(true);
        store_connector_runtime(&f, &runtime)?;
        let rebound = tangled_review::rebind_credentials(&f.state(), &f.config())?;
        let mut unchanged = rebound.clone();
        unchanged["credential_history"] = prior["credential_history"].clone();
        assert_eq!(
            unchanged, prior,
            "only the credential history changes: {stage}"
        );
        assert_eq!(
            f.data.lock().map_err(|e| e.to_string())?["writes"],
            writes,
            "rebind must not write: {stage}"
        );
        assert_eq!(
            connector_runtime(&f)?["writes"],
            actor_writes,
            "rebind must not attest: {stage}"
        );
        let result = if stage == "ticket_pending" {
            select_and_reconcile(&f)?
        } else {
            tangled_review::reconcile(&f.state(), &f.config())?
        };
        assert_eq!(result["phase"], "submitted", "{stage}");
        assert_eq!(result["attempt"], prior["attempt"], "{stage}");
        assert_eq!(
            f.data.lock().map_err(|e| e.to_string())?["writes"],
            2,
            "each knot write occurs once: {stage}"
        );
        let runtime = connector_runtime(&f)?;
        assert_eq!(
            runtime["writes"], 2,
            "each actor write occurs once: {stage}"
        );
        if stage == "attestation_pending" {
            let original = &prior["attestations"][0]["request"];
            assert_eq!(result["attestations"][0]["request"], *original);
            let calls = runtime["calls"].as_array().ok_or("calls")?;
            let recovered = calls
                .iter()
                .find(|c| {
                    c["action"] == "reconcile"
                        && c["request"]["request_id"] == original["request_id"]
                })
                .ok_or("missing readback")?;
            assert_eq!(recovered["request"]["generation"], 2);
            assert_eq!(recovered["request"]["body"], original["body"]);
        }
    }
    Ok(())
}

#[test]
fn credential_rebind_preserves_uncertain_missing_patch_without_retry() -> Result {
    let f = Fixture::new(true)?;
    typed_connector(&f, false)?;
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    f.data.lock().map_err(|e| e.to_string())?["patches"] = json!([]);
    advance_credentials(&f, 2)?;
    let rebound = tangled_review::rebind_credentials(&f.state(), &f.config())?;
    assert_eq!(rebound["phase"], "patch_pending");
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(review_receipt(&f)?, rebound);
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}

#[test]
fn credential_rebind_rejects_policy_substitution_and_unverified_accounts() -> Result {
    for field in [
        "account",
        "connection",
        "knot",
        "repository",
        "source_repository",
        "web_url",
        "unavailable",
        "account_response",
    ] {
        let f = Fixture::new(false)?;
        typed_connector(&f, false)?;
        let prior = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
        advance_credentials(&f, 2)?;
        let mut c: Value = serde_json::from_slice(&fs::read(f.config())?)?;
        let host_path = f.root.path().join("host.json");
        let mut host: Value = serde_json::from_slice(&fs::read(&host_path)?)?;
        match field {
            "account" | "connection" => {
                let value = if field == "account" {
                    json!("did:plc:other")
                } else {
                    json!(2)
                };
                c["connector"][field] = value.clone();
                host[field] = value;
            }
            "knot" | "repository" | "source_repository" => {
                let value = if field == "knot" {
                    json!("https://other.example")
                } else {
                    json!("did:plc:other")
                };
                c[field] = value.clone();
                host[field] = value;
            }
            "web_url" => c[field] = json!("https://other.example/project"),
            "unavailable" | "account_response" => {
                let mut runtime = connector_runtime(&f)?;
                if field == "unavailable" {
                    runtime["available"] = json!(false);
                } else {
                    runtime["account_override"] = json!("did:plc:other");
                }
                store_connector_runtime(&f, &runtime)?;
            }
            _ => return Err("invalid refusal case".into()),
        }
        fs::write(f.config(), serde_json::to_vec(&c)?)?;
        fs::write(host_path, serde_json::to_vec(&host)?)?;
        assert!(
            tangled_review::rebind_credentials(&f.state(), &f.config()).is_err(),
            "{field}"
        );
        assert_eq!(review_receipt(&f)?, prior, "{field}");
        assert_eq!(
            f.data.lock().map_err(|e| e.to_string())?["writes"],
            2,
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn credential_rebind_replays_interrupted_transition_and_keeps_confirmed_attempts() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    let first = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    let attempt = first["attempt"].as_str().ok_or("attempt")?;
    let archived = f.state().join("review-attempts").join(attempt);
    let original_intent = fs::read(archived.join("intent.json"))?;
    let original_confirmed = fs::read(archived.join("confirmed.json"))?;
    assert!(tangled_review::rebind_credentials(&f.state(), &f.config()).is_err());
    advance_credentials(&f, 2)?;
    let rebound = tangled_review::rebind_credentials(&f.state(), &f.config())?;
    let transition = fs::read(archived.join("credential-rebind-2.json"))?;
    // Crash boundary: immutable transition survives, active journal is still old.
    fs::write(f.state().join("review.json"), serde_json::to_vec(&first)?)?;
    assert_eq!(
        tangled_review::rebind_credentials(&f.state(), &f.config())?,
        rebound
    );
    assert_eq!(
        tangled_review::rebind_credentials(&f.state(), &f.config())?,
        rebound
    );
    assert_eq!(
        fs::read(archived.join("credential-rebind-2.json"))?,
        transition
    );
    assert_eq!(fs::read(archived.join("intent.json"))?, original_intent);
    assert_eq!(
        fs::read(archived.join("confirmed.json"))?,
        original_confirmed
    );
    assert_eq!(tangled_review::reconcile(&f.state(), &f.config())?, rebound);
    f.publication("cccccccccccccccccccccccccccccccccccccccc")?;
    let mut input = f.input();
    input.resubmit = true;
    input.ticket_key = "79".into();
    let second = tangled_review::submit(&f.state(), &f.config(), &input)?;
    assert_eq!(second["previous"]["attempt"], first["attempt"]);
    assert_eq!(second["connector_authority"]["generation"], 2);
    assert_eq!(
        fs::read(archived.join("confirmed.json"))?,
        original_confirmed
    );
    Ok(())
}

#[test]
fn credential_rebind_refuses_legacy_and_receipts_without_retained_binding() -> Result {
    let f = Fixture::new(false)?;
    let legacy = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert!(tangled_review::rebind_credentials(&f.state(), &f.config()).is_err());
    assert_eq!(review_receipt(&f)?, legacy);
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    let mut old = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    old["schema_version"] = json!(1);
    old.as_object_mut()
        .ok_or("receipt")?
        .remove("connector_authority");
    old.as_object_mut()
        .ok_or("receipt")?
        .remove("credential_history");
    fs::write(f.state().join("review.json"), serde_json::to_vec(&old)?)?;
    advance_credentials(&f, 2)?;
    assert!(tangled_review::rebind_credentials(&f.state(), &f.config()).is_err());
    assert_eq!(review_receipt(&f)?, old);
    Ok(())
}

#[test]
fn integration_fork_merge_admission_refuses_before_signing_or_push() -> Result {
    let f = Fixture::new(false)?;
    let mut config: Value = serde_json::from_slice(&fs::read(f.config())?)?;
    config["source_repository"] = json!("did:plc:fork");
    fs::write(f.config(), serde_json::to_vec(&config)?)?;
    let mut publication: Value =
        serde_json::from_slice(&fs::read(f.state().join("publication.json"))?)?;
    publication["destination"] = json!(format!("{}/did:plc:fork", f.url));
    fs::write(
        f.state().join("publication.json"),
        serde_json::to_vec(&publication)?,
    )?;
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    let error =
        tangled_review::merge_admission(&f.state(), &f.config(), &"a".repeat(40), &"b".repeat(40))
            .err()
            .ok_or("fork merge admitted")?;
    let options = ladyshell::review_merge::Options {
        config: &f.config(),
        policy: &f.root.path().join("unneeded-policy"),
        remote: "knot",
        branch: "main",
        head: &"a".repeat(40),
        expected: &"b".repeat(40),
    };
    let refused = ladyshell::review_merge::check(&f.state(), &options)
        .err()
        .ok_or("fork preflight admitted")?;
    assert!(refused.to_string().contains("same repository"), "{refused}");
    assert!(error.to_string().contains("same repository"), "{error}");
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    assert!(!f.state().join("merge.json").exists());
    Ok(())
}

#[test]
fn integration_ci_feedback_accounts_for_total_workflows_and_exact_commit() -> Result {
    let f = Fixture::new(false)?;
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    let pipeline =
        json!({"repo":"did:plc:repo","commit":"a".repeat(40),"workflows":[{"status":"success"}]});
    let mut cases = vec![
        (json!({"total":1,"pipelines":[pipeline.clone()]}), "success"),
        (json!({"total":2,"pipelines":[pipeline.clone()]}), "unknown"),
        (json!({"pipelines":[pipeline.clone()]}), "unknown"),
        (
            json!({"total":-1,"pipelines":[pipeline.clone()]}),
            "unknown",
        ),
        (json!({"total":0,"pipelines":[pipeline.clone()]}), "unknown"),
        (
            json!({"total":1,"pipelines":[pipeline.clone()],"cursor":"more"}),
            "unknown",
        ),
    ];
    for workflows in [
        Value::Null,
        json!([]),
        json!([{"status":"invented"}]),
        json!([{}]),
    ] {
        let mut p = pipeline.clone();
        p["workflows"] = workflows;
        cases.push((json!({"total":1,"pipelines":[p]}), "unknown"));
    }
    let mut wrong = pipeline.clone();
    wrong["commit"] = json!("f".repeat(40));
    cases.push((json!({"total":1,"pipelines":[wrong]}), "unknown"));
    let mut incomplete = pipeline.clone();
    incomplete
        .as_object_mut()
        .ok_or("pipeline")?
        .remove("workflows");
    cases.push((
        json!({"total":2,"pipelines":[pipeline.clone(),incomplete]}),
        "unknown",
    ));
    let mut failed = pipeline;
    failed["workflows"][0]["status"] = json!("failed");
    cases.push((json!({"total":1,"pipelines":[failed]}), "failed"));
    for (page, expected) in cases {
        f.data.lock().map_err(|e| e.to_string())?["ci"] = page.clone();
        let feedback = tangled_review::feedback(&f.state(), &f.config())?;
        assert_eq!(feedback["ci"]["status"], expected, "{page}");
        assert_eq!(feedback["ci"]["commit"], "a".repeat(40));
        assert_eq!(feedback["ci"]["acceptance_authority"], false);
        if expected == "unknown" {
            assert_eq!(feedback["ci"]["complete"], false);
        }
    }
    f.data.lock().map_err(|e| e.to_string())?["ci_unavailable"] = json!(true);
    assert_eq!(
        tangled_review::feedback(&f.state(), &f.config())?["ci"]["status"],
        "unknown"
    );
    f.data.lock().map_err(|e| e.to_string())?["ci_unavailable"] = json!(false);
    tangled_review::feedback(&f.state(), &f.config())?;
    let state = json!({"schema_version":2,"sandbox_name":"agent","sandbox_id":"bound-id","policy_hash":"policy","codex_binary":"/codex","owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"source","build_dir":"build","context":{"gateway":"test","workspace":"default"}});
    fs::write(f.state().join("state.json"), serde_json::to_vec(&state)?)?;
    struct Delivery(Vec<u8>);
    impl tangled_review::FeedbackDriver for Delivery {
        fn deliver(&mut self, _: &Value, bytes: &[u8]) -> ladyshell::error::Result<()> {
            self.0 = bytes.to_vec();
            Ok(())
        }
    }
    let mut driver = Delivery(Vec::new());
    tangled_review::deliver_feedback_with(&f.state(), &mut driver)?;
    let delivered: Value = serde_json::from_slice(&driver.0)?;
    assert_eq!(delivered["ci"]["status"], "failed");
    assert_eq!(delivered["ci"]["acceptance_authority"], false);
    assert_eq!(delivered["required_checks"]["status"], "unknown");
    let mut review = review_receipt(&f)?;
    review["required_checks"] = json!({"publication_head":"a".repeat(40),"receipt":{"schema_version":1,"export":"/private/export","snapshot_sha256":"1".repeat(64),"policy_sha256":"2".repeat(64),"commands":["read /private/policy"],"passed":true,"cleanup_confirmed":true,"results":[{"command":"read /private/policy","output_sha256":"3".repeat(64),"exit_code":0}],"verifier":{"private":"SECRET"}}});
    fs::write(f.state().join("review.json"), serde_json::to_vec(&review)?)?;
    let feedback = tangled_review::feedback(&f.state(), &f.config())?;
    assert_eq!(feedback["required_checks"]["status"], "success");
    assert_eq!(
        feedback["required_checks"]["snapshot_sha256"],
        "1".repeat(64)
    );
    assert!(!feedback.to_string().contains("/private"));
    assert!(!feedback.to_string().contains("SECRET"));
    review["required_checks"]["publication_head"] = json!("f".repeat(40));
    fs::write(f.state().join("review.json"), serde_json::to_vec(&review)?)?;
    assert_eq!(
        tangled_review::feedback(&f.state(), &f.config())?["required_checks"]["status"],
        "unknown"
    );
    Ok(())
}

#[test]
fn display_states_preserve_exact_round_and_informational_ci() -> Result {
    let f = Fixture::new(false)?;
    let draft = tangled_review::status(&f.state(), &f.config())?;
    assert_eq!(draft["display_state"], "draft");
    assert_eq!(draft["human_review"]["status"], "unknown");
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["display_state"],
        "unknown"
    );
    f.data.lock().unwrap()["ci"] = json!({"total":1,"pipelines":[{"repo":"did:plc:repo","commit":"a".repeat(40),"workflows":[{"status":"success"}]}]});
    let requested = tangled_review::status(&f.state(), &f.config())?;
    assert_eq!(requested["display_state"], "requested_review");
    assert_eq!(requested["ci"]["acceptance_authority"], false);
    f.data.lock().unwrap()["ci"]["pipelines"][0]["workflows"][0]["status"] = json!("failed");
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["display_state"],
        "checks_failed"
    );
    f.publication(&"c".repeat(40))?;
    let ahead = tangled_review::status(&f.state(), &f.config())?;
    assert_eq!(ahead["source_ahead"], true);
    assert_eq!(ahead["submitted_head"], "a".repeat(40));
    assert_eq!(ahead["current_source_head"], "c".repeat(40));
    let mut newer = f.data.lock().unwrap()["patches"][0].clone();
    newer["uri"] = json!("at://did:plc:repo/org.tangled.review.patch/newer");
    newer["value"]["createdAt"] = json!("2026-11-05T00:01:00Z");
    f.data.lock().unwrap()["patches"]
        .as_array_mut()
        .unwrap()
        .push(newer);
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["display_state"],
        "superseded_round"
    );
    Ok(())
}

fn fixture_git(project: &std::path::Path, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(project)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().into())
}

struct MergeFixture {
    review: Fixture,
    policy: std::path::PathBuf,
    config: std::path::PathBuf,
    remote: std::path::PathBuf,
    export: std::path::PathBuf,
    base: String,
    head: String,
}
impl MergeFixture {
    fn new() -> Result<Self> {
        Self::with_signature(true)
    }
    fn with_signature(signed: bool) -> Result<Self> {
        Self::with_profile(signed, false)
    }
    fn with_profile(signed: bool, required: bool) -> Result<Self> {
        let f = Fixture::new(false)?;
        let root = f.root.path();
        let project = root.join("project");
        let remote = root.join("remote.git");
        fs::create_dir(&remote)?;
        fixture_git(&remote, &["init", "--bare"])?;
        fixture_git(&project, &["init", "-b", "main"])?;
        fixture_git(&project, &["config", "user.name", "Fixture"])?;
        fixture_git(
            &project,
            &["config", "user.email", "fixture@example.invalid"],
        )?;
        fs::write(project.join("code"), b"base\n")?;
        fixture_git(&project, &["add", "."])?;
        fixture_git(&project, &["commit", "-m", "base"])?;
        let base = fixture_git(&project, &["rev-parse", "HEAD"])?;
        fixture_git(
            &project,
            &[
                "push",
                remote.to_str().ok_or("path")?,
                "HEAD:refs/heads/main",
            ],
        )?;
        let key = root.join("key");
        let output = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()?;
        assert!(output.status.success());
        let allowed = root.join("allowed");
        fs::write(
            &allowed,
            format!(
                "host@example.invalid {}",
                fs::read_to_string(key.with_extension("pub"))?
            ),
        )?;
        fixture_git(&project, &["config", "gpg.format", "ssh"])?;
        fixture_git(
            &project,
            &["config", "user.signingkey", key.to_str().ok_or("key")?],
        )?;
        fs::write(project.join("code"), b"reviewed\n")?;
        fixture_git(
            &project,
            if signed {
                &["commit", "-S", "-am", "reviewed"]
            } else {
                &["commit", "-am", "reviewed"]
            },
        )?;
        let head = fixture_git(&project, &["rev-parse", "HEAD"])?;
        // Local SSH transport adapter invokes real Git upload/receive-pack on
        // the fixture repository. It supplies no server identity evidence.
        let ssh = root.join("ssh-fixture");
        fs::write(&ssh, format!("#!/usr/bin/python3\nimport sys,shlex,os\nif '-G' in sys.argv: sys.exit(0)\ncmd=shlex.split(sys.argv[-1])\nassert cmd[0] in ('git-upload-pack','git-receive-pack')\nos.execvp(cmd[0],[cmd[0],{}])\n", serde_json::to_string(&remote)?))?;
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700))?;
        fixture_git(
            &project,
            &["config", "core.sshCommand", ssh.to_str().ok_or("ssh")?],
        )?;
        let destination = "git@127.0.0.1:did:plc:repo";
        fixture_git(&project, &["remote", "add", "knot", destination])?;
        let export = root.join("export");
        fs::create_dir_all(export.join("project"))?;
        fs::write(export.join("project/code"), b"reviewed\n")?;
        let inventory = ladyshell::snapshot::inventory(&export.join("project"))?;
        let files: serde_json::Map<String, Value> = inventory
            .iter()
            .map(|(p, e)| {
                (
                    p.clone(),
                    json!({"sha256":e.sha256,"executable":e.executable}),
                )
            })
            .collect();
        fs::write(
            export.join("manifest.json"),
            serde_json::to_vec(&json!({"schema_version":2,"files":files}))?,
        )?;
        let checks = ladyshell::publication_checks::CheckPolicy {
            commands: vec![vec!["true".into()]],
            timeout: 30,
        };
        // Protocol fixture receipt, not a claim of native verifier execution.
        fs::write(
            export.join("checks.json"),
            serde_json::to_vec(
                &json!({"schema_version":1,"passed":true,"snapshot_sha256":ladyshell::publication_checks::export_digest(&export)?,"policy_sha256":ladyshell::files::hash(&serde_json::to_vec(&checks)?)}),
            )?,
        )?;
        let policy = root.join("policy.json");
        fs::write(
            &policy,
            serde_json::to_vec(
                &json!({"schema_version":1,"checks":checks,"signing":{"key":key,"allowed_signers":allowed,"principal":"host@example.invalid","program":"/usr/bin/ssh-keygen"}}),
            )?,
        )?;
        fs::write(
            f.state().join("publication.json"),
            serde_json::to_vec(
                &json!({"schema_version":2,"phase":"published","confirmed":true,"project":project,"export":export,"destination":destination,"reference":"refs/heads/draft","base":base,"commit":head}),
            )?,
        )?;
        if required {
            let mut config: Value = serde_json::from_slice(&fs::read(f.config())?)?;
            config["require_owner_review"] = json!(true);
            fs::write(f.config(), serde_json::to_vec(&config)?)?;
        }
        let mut input = f.input();
        input.target_base = base.clone();
        tangled_review::submit(&f.state(), &f.config(), &input)?;
        let config = f.config();
        Ok(Self {
            review: f,
            policy,
            config,
            remote,
            export,
            base,
            head,
        })
    }
    fn options(&self) -> ladyshell::review_merge::Options<'_> {
        // Config's stable host pathname is retained by the fixture root.
        ladyshell::review_merge::Options {
            config: &self.config,
            policy: &self.policy,
            remote: "knot",
            branch: "main",
            head: &self.head,
            expected: &self.base,
        }
    }
}

// Compare persistent fixture content, including Git objects, refs, receipts,
// archives and check evidence. Advisory lock files are permitted observations.
type PersistentTree = std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>;
fn persistent_tree(root: &std::path::Path) -> Result<PersistentTree> {
    fn visit(
        root: &std::path::Path,
        path: &std::path::Path,
        result: &mut PersistentTree,
    ) -> Result {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_name() == ".lock" || entry.file_name() == ".sessions" {
                continue;
            }
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                result.insert(path.strip_prefix(root)?.to_owned(), None);
                visit(root, &path, result)?;
            } else {
                result.insert(path.strip_prefix(root)?.to_owned(), Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut result = std::collections::BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}

#[test]
fn merge_check_is_nonpublishing_and_merge_rechecks_current_admission() -> Result {
    let f = MergeFixture::new()?;
    let before = fs::read(f.review.state().join("review.json"))?;
    let index = fs::read(f.review.root.path().join("project/.git/index"))?;
    let persistent_before = persistent_tree(f.review.root.path())?;
    let writes_before = f.review.data.lock().unwrap()["writes"].clone();
    let ready = ladyshell::review_merge::check(&f.review.state(), &f.options())?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["review", "merge-check", "--state"])
        .arg(f.review.state())
        .arg("--config")
        .arg(&f.config)
        .arg("--policy")
        .arg(&f.policy)
        .args([
            "--remote",
            "knot",
            "--branch",
            "main",
            "--head",
            &f.head,
            "--expected-target",
            &f.base,
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(serde_json::from_slice::<Value>(&output.stdout)?, ready);
    assert_eq!(persistent_tree(f.review.root.path())?, persistent_before);
    assert_eq!(f.review.data.lock().unwrap()["writes"], writes_before);
    assert_eq!(ready["display_state"], "ready_to_merge");
    assert_eq!(ready["acceptance_authority"], false);
    assert_eq!(ready["head"], f.head);
    assert_eq!(ready["expected_target"], f.base);
    assert!(!ready
        .to_string()
        .contains(f.review.root.path().to_str().ok_or("path")?));
    assert_eq!(fs::read(f.review.state().join("review.json"))?, before);
    assert_eq!(
        fs::read(f.review.root.path().join("project/.git/index"))?,
        index
    );
    assert!(!f.review.state().join("merge.json").exists());
    assert!(!f.review.state().join("merge-attempts").exists());
    assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.base);
    f.review.data.lock().unwrap()["ticket"]["state"] = json!("closed");
    assert!(ladyshell::review_merge::run(&f.review.state(), &f.options()).is_err());
    assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.base);
    f.review.data.lock().unwrap()["ticket"]["state"] = json!("open");
    assert_eq!(
        ladyshell::review_merge::run(&f.review.state(), &f.options())?["confirmed"],
        true
    );
    assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.head);
    Ok(())
}

#[test]
fn merge_check_refuses_missing_checks_signer_and_guard_evidence_without_archive_writes() -> Result {
    let f = MergeFixture::new()?;
    let pointer = json!({"confirmed":true,"previous":"retained"});
    fs::write(
        f.review.state().join("merge.json"),
        serde_json::to_vec(&pointer)?,
    )?;
    let checks_path = f.export.join("checks.json");
    let checks = fs::read(&checks_path)?;
    fs::remove_file(&checks_path)?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    let mut failed: Value = serde_json::from_slice(&checks)?;
    failed["passed"] = json!(false);
    fs::write(&checks_path, serde_json::to_vec(&failed)?)?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    fs::write(&checks_path, checks)?;
    let policy = fs::read(&f.policy)?;
    let mut wrong: Value = serde_json::from_slice(&policy)?;
    wrong["signing"]["principal"] = json!("wrong@example.invalid");
    fs::write(&f.policy, serde_json::to_vec(&wrong)?)?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    let revoked = f.review.root.path().join("revoked");
    fs::write(&revoked, fs::read(f.review.root.path().join("key.pub"))?)?;
    wrong = serde_json::from_slice(&policy)?;
    wrong["signing"]["revocation_file"] = json!(revoked);
    fs::write(&f.policy, serde_json::to_vec(&wrong)?)?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    fs::write(&f.policy, policy)?;
    let session = ladyshell::state::SessionLock::acquire(&f.review.state(), false)?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    drop(session);
    let parent = f.review.root.path().join("parent");
    ladyshell::state::create_directory(&parent)?;
    fs::write(
        parent.join("publication.json"),
        serde_json::to_vec(&json!({"confirmed":true,"base":f.base,"commit":f.head}))?,
    )?;
    fs::write(
        f.review.state().join("stack-binding.json"),
        serde_json::to_vec(
            &json!({"schema_version":1,"stack":parent,"parent":parent,"parent_head":f.base}),
        )?,
    )?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    fs::remove_file(f.review.state().join("stack-binding.json"))?;
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(f.review.state().join("merge.json"))?)?,
        pointer
    );
    assert!(!f.review.state().join("merge-attempts").exists());
    fs::write(
        f.review.state().join("merge.json"),
        b"{\"confirmed\":false}",
    )?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    assert!(!f.review.state().join("merge-attempts").exists());
    Ok(())
}

#[test]
fn readiness_observation_does_not_survive_target_round_or_check_policy_changes() -> Result {
    for change in ["target", "round", "policy"] {
        let f = MergeFixture::new()?;
        ladyshell::review_merge::check(&f.review.state(), &f.options())?;
        match change {
            "target" => {
                fixture_git(
                    &f.review.root.path().join("project"),
                    &[
                        "push",
                        f.remote.to_str().ok_or("remote")?,
                        "HEAD:refs/heads/main",
                    ],
                )?;
            }
            "round" => {
                let mut newer = f.review.data.lock().unwrap()["patches"][0].clone();
                newer["uri"] = json!("at://did:plc:repo/org.tangled.review.patch/newer");
                newer["value"]["createdAt"] = json!("2026-11-05T00:01:00Z");
                f.review.data.lock().unwrap()["patches"]
                    .as_array_mut()
                    .unwrap()
                    .push(newer);
            }
            _ => {
                let mut policy: Value = serde_json::from_slice(&fs::read(&f.policy)?)?;
                policy["checks"]["commands"] = json!([["false"]]);
                fs::write(&f.policy, serde_json::to_vec(&policy)?)?;
            }
        }
        assert!(
            ladyshell::review_merge::run(&f.review.state(), &f.options()).is_err(),
            "{change}"
        );
        assert!(!f.review.state().join("merge.json").exists());
        assert!(!f.review.state().join("merge-attempts").exists());
    }
    Ok(())
}

#[test]
fn display_state_never_labels_closed_missing_or_ambiguous_evidence_requested() -> Result {
    let f = Fixture::new(false)?;
    tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    f.data.lock().unwrap()["ci"] = json!({"total":1,"pipelines":[{"repo":"did:plc:repo","commit":"a".repeat(40),"workflows":[{"status":"success"}]}]});
    f.data.lock().unwrap()["ticket"]["state"] = json!("closed");
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["display_state"],
        "unknown"
    );
    f.data.lock().unwrap()["ticket"]["state"] = json!("open");
    let mut patch = f.data.lock().unwrap()["patches"][0].clone();
    patch["uri"] = json!("at://did:plc:repo/org.tangled.review.patch/ambiguous");
    f.data.lock().unwrap()["patches"]
        .as_array_mut()
        .unwrap()
        .push(patch);
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["display_state"],
        "unknown"
    );
    f.data.lock().unwrap()["patches"] = json!([]);
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["display_state"],
        "unknown"
    );
    fs::write(f.state().join("review.json"), b"{}")?;
    assert!(tangled_review::status(&f.state(), &f.config()).is_err());
    Ok(())
}

#[test]
fn merge_check_rejects_unsigned_exact_commit() -> Result {
    let f = MergeFixture::with_signature(false)?;
    let refused = ladyshell::review_merge::check(&f.review.state(), &f.options());
    assert!(refused.is_err());
    assert!(!f.review.state().join("merge.json").exists());
    assert!(!f.review.state().join("merge-attempts").exists());
    Ok(())
}

#[test]
fn host_owner_required_profile_refuses_missing_decision() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    assert!(ladyshell::review_merge::run(&f.review.state(), &f.options()).is_err());
    assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.base);
    Ok(())
}

fn owner_input(f: &MergeFixture, decision: &str) -> Result<tangled_review::DecisionInput> {
    Ok(serde_json::from_value(
        json!({"decision":decision,"head":f.head,"base":f.base,"patch_uri":"at://did:plc:repo/org.tangled.review.patch/round1","patch_cid":"roundcid","explanation":"Exact host review; untrusted explanatory text"}),
    )?)
}

#[test]
fn host_owner_approval_withdrawal_history_and_feedback_bind_exact_round() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    let input = owner_input(&f, "approved")?;
    let writes = f.review.data.lock().unwrap()["writes"].clone();
    let review_before = fs::read(f.review.state().join("review.json"))?;
    let index = fs::read(f.review.root.path().join("project/.git/index"))?;
    let marker = f.review.root.path().join("unexpected-auth-command");
    fs::write(
        f.review.root.path().join("auth"),
        format!("#!/bin/sh\ntouch {}\nexit 1\n", marker.display()),
    )?;
    let first = tangled_review::record_owner_decision(&f.review.state(), &f.config, &input)?;
    let cli = std::process::Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["review", "owner-decision", "--state"])
        .arg(f.review.state())
        .arg("--config")
        .arg(&f.config)
        .args([
            "--decision",
            "approved",
            "--head",
            &f.head,
            "--base",
            &f.base,
            "--patch-uri",
            &input.patch_uri,
            "--patch-cid",
            &input.patch_cid,
            "--explanation",
            input.explanation.as_deref().ok_or("explanation")?,
        ])
        .output()?;
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    assert_eq!(serde_json::from_slice::<Value>(&cli.stdout)?, first);
    assert!(!marker.exists());
    assert_eq!(first["source"], "host_owner");
    assert_eq!(first["status"], "current");
    assert_eq!(first["decision"], "approved");
    assert_eq!(
        tangled_review::record_owner_decision(&f.review.state(), &f.config, &input)?,
        first
    );
    let history = f.review.state().join("owner-review-decisions");
    assert_eq!(fs::read_dir(&history)?.count(), 1);
    let immutable = persistent_tree(&history)?;
    let ready = ladyshell::review_merge::check(&f.review.state(), &f.options())?;
    assert_eq!(ready["human_review"], first);
    assert_eq!(
        tangled_review::feedback(&f.review.state(), &f.config)?["human_review"],
        first
    );
    assert_eq!(f.review.data.lock().unwrap()["writes"], writes);
    assert_eq!(
        fs::read(f.review.state().join("review.json"))?,
        review_before
    );
    assert_eq!(
        fs::read(f.review.root.path().join("project/.git/index"))?,
        index
    );
    assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.base);
    assert!(!first
        .to_string()
        .contains(f.review.root.path().to_str().ok_or("path")?));
    for decision in ["changes_requested", "withdrawn"] {
        let current = tangled_review::record_owner_decision(
            &f.review.state(),
            &f.config,
            &owner_input(&f, decision)?,
        )?;
        assert_eq!(current["decision"], decision);
        if decision == "changes_requested" {
            assert_eq!(
                tangled_review::status(&f.review.state(), &f.config)?["display_state"],
                "changes_requested"
            );
        }
        assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
        assert!(ladyshell::review_merge::run(&f.review.state(), &f.options()).is_err());
    }
    assert_eq!(fs::read_dir(&history)?.count(), 3);
    for (name, bytes) in immutable {
        assert_eq!(persistent_tree(&history)?.get(&name), Some(&bytes));
    }
    assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.base);
    Ok(())
}

#[test]
fn host_owner_decisions_reject_substitution_guards_and_do_not_require_technical_success() -> Result
{
    let f = MergeFixture::with_profile(false, true)?;
    for field in ["head", "base", "patch_uri", "patch_cid"] {
        let mut input = serde_json::to_value(owner_input(&f, "approved")?)?;
        input[field] = json!(if field == "head" || field == "base" {
            "cccccccccccccccccccccccccccccccccccccccc"
        } else {
            "different"
        });
        assert!(tangled_review::record_owner_decision(
            &f.review.state(),
            &f.config,
            &serde_json::from_value(input)?
        )
        .is_err());
    }
    let sessions = ladyshell::state::SessionLock::acquire(&f.review.state(), false)?;
    assert!(tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?
    )
    .is_err());
    drop(sessions);
    let parent = f.review.root.path().join("parent");
    ladyshell::state::create_directory(&parent)?;
    fs::write(
        parent.join("publication.json"),
        serde_json::to_vec(&json!({"confirmed":true,"base":f.base,"commit":f.head}))?,
    )?;
    fs::write(
        f.review.state().join("stack-binding.json"),
        serde_json::to_vec(
            &json!({"schema_version":1,"stack":parent,"parent":parent,"parent_head":f.base}),
        )?,
    )?;
    assert!(tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?
    )
    .is_err());
    fs::remove_file(f.review.state().join("stack-binding.json"))?;
    let mut oversized = owner_input(&f, "approved")?;
    oversized.explanation = Some("x".repeat(2049));
    assert!(
        tangled_review::record_owner_decision(&f.review.state(), &f.config, &oversized).is_err()
    );
    // An approval still cannot bypass an unsigned commit or missing checks.
    tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?,
    )?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    fs::remove_file(f.export.join("checks.json"))?;
    let requested = tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "changes_requested")?,
    )?;
    assert_eq!(requested["decision"], "changes_requested");
    assert!(!f.review.state().join("merge.json").exists());
    Ok(())
}

#[test]
fn host_owner_history_malformed_or_missing_sequence_fails_closed() -> Result {
    for damage in ["malformed", "gap", "symlink", "extra_field", "oversized"] {
        let f = MergeFixture::with_profile(true, true)?;
        tangled_review::record_owner_decision(
            &f.review.state(),
            &f.config,
            &owner_input(&f, "approved")?,
        )?;
        let history = f.review.state().join("owner-review-decisions");
        let first = fs::read_dir(&history)?.next().ok_or("record")??.path();
        match damage {
            "malformed" => fs::write(&first, b"{}")?,
            "gap" => fs::rename(&first, history.join("00000000000000000002.json"))?,
            "symlink" => {
                fs::remove_file(&first)?;
                std::os::unix::fs::symlink(f.review.root.path().join("config.json"), &first)?;
            }
            "oversized" => fs::write(&first, vec![b' '; 17000])?,
            _ => {
                let mut value: Value = serde_json::from_slice(&fs::read(&first)?)?;
                value["extra"] = json!(true);
                fs::write(&first, serde_json::to_vec(&value)?)?;
            }
        }
        assert!(
            ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err(),
            "{damage}"
        );
        assert!(
            tangled_review::record_owner_decision(
                &f.review.state(),
                &f.config,
                &owner_input(&f, "approved")?
            )
            .is_err(),
            "{damage}"
        );
        assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.base);
    }
    Ok(())
}

#[test]
fn host_owner_decision_stales_on_source_round_and_policy_changes() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?,
    )?;
    let publication_path = f.review.state().join("publication.json");
    let publication = fs::read(&publication_path)?;
    let mut advanced: Value = serde_json::from_slice(&publication)?;
    advanced["commit"] = json!("cccccccccccccccccccccccccccccccccccccccc");
    fs::write(&publication_path, serde_json::to_vec(&advanced)?)?;
    let status = tangled_review::status(&f.review.state(), &f.config)?;
    assert_eq!(status["human_review"]["status"], "stale");
    assert!(tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?
    )
    .is_err());
    assert!(ladyshell::review_merge::run(&f.review.state(), &f.options()).is_err());
    fs::write(&publication_path, &publication)?;
    // A new immutable round needs a new explicit decision, even with the same
    // source commit. The provider can supersede the retained submitted round.
    let patches = f.review.data.lock().unwrap()["patches"].clone();
    let mut newer = patches[0].clone();
    newer["uri"] = json!("at://did:plc:repo/org.tangled.review.patch/round2");
    newer["cid"] = json!("different-cid");
    newer["value"]["createdAt"] = json!("2026-11-05T00:00:02Z");
    f.review.data.lock().unwrap()["patches"]
        .as_array_mut()
        .ok_or("patches")?
        .push(newer);
    let status = tangled_review::status(&f.review.state(), &f.config)?;
    assert_eq!(status["display_state"], "superseded_round");
    assert_eq!(status["human_review"]["status"], "stale");
    assert!(ladyshell::review_merge::run(&f.review.state(), &f.options()).is_err());
    f.review.data.lock().unwrap()["patches"] = patches;
    let mut config: Value = serde_json::from_slice(&fs::read(&f.config)?)?;
    config["web_url"] = json!(format!("{}/changed/policy", f.review.url));
    fs::write(&f.config, serde_json::to_vec(&config)?)?;
    assert!(ladyshell::review_merge::run(&f.review.state(), &f.options()).is_err());
    assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.base);
    Ok(())
}

#[test]
fn host_owner_withdrawal_blocks_uncertain_retry_but_allows_exact_accepted_readback() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    let approved = tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?,
    )?;
    let admission =
        tangled_review::merge_admission(&f.review.state(), &f.config, &f.head, &f.base)?;
    let policy = ladyshell::publication_policy::Policy::load(
        &f.policy,
        &f.review.root.path().join("project"),
    )?;
    let intent = json!({"schema_version":1,"project":f.review.root.path().join("project"),"export":f.export,"head":f.head,"expected_target":f.base,"reference":"refs/heads/main","destination":"git@127.0.0.1:did:plc:repo","confirmed":false,"review":admission,"review_config":f.config,"policy":f.policy,"policy_digests":policy.digests,"strategy":"signed_fast_forward"});
    fs::write(
        f.review.state().join("merge.json"),
        serde_json::to_vec(&intent)?,
    )?;
    tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "withdrawn")?,
    )?;
    assert!(ladyshell::review_merge::reconcile(&f.review.state(), true).is_err());
    assert_eq!(fixture_git(&f.remote, &["rev-parse", "main"])?, f.base);
    assert_eq!(
        ladyshell::review_merge::reconcile(&f.review.state(), false)?["confirmed"],
        false
    );
    // Model an already accepted transport write, whose acknowledgement was lost.
    fixture_git(
        &f.review.root.path().join("project"),
        &["push", "knot", &format!("{}:refs/heads/main", f.head)],
    )?;
    let confirmed = ladyshell::review_merge::reconcile(&f.review.state(), true)?;
    assert_eq!(confirmed["confirmed"], true);
    assert_eq!(confirmed["review"]["review"]["human_review"], approved);
    assert_eq!(
        tangled_review::status(&f.review.state(), &f.config)?["human_review"]["decision"],
        "withdrawn"
    );
    Ok(())
}

#[test]
fn host_owner_policy_keeps_legacy_serialization_and_same_owner_rebind_compatible() -> Result {
    let f = Fixture::new(false)?;
    let legacy: tangled_review::Config = serde_json::from_slice(&fs::read(f.config())?)?;
    assert!(!legacy.require_owner_review);
    assert!(serde_json::to_value(legacy)?
        .get("require_owner_review")
        .is_none());
    typed_connector(&f, false)?;
    let mut config: Value = serde_json::from_slice(&fs::read(f.config())?)?;
    config["require_owner_review"] = json!(true);
    fs::write(f.config(), serde_json::to_vec(&config)?)?;
    let review = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    let input = serde_json::from_value(
        json!({"decision":"approved","head":review["submitted_head"],"base":review["submitted_base"],"patch_uri":review["patch"]["uri"],"patch_cid":review["patch"]["cid"]}),
    )?;
    let approved = tangled_review::record_owner_decision(&f.state(), &f.config(), &input)?;
    advance_credentials(&f, 2)?;
    tangled_review::rebind_credentials(&f.state(), &f.config())?;
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["human_review"],
        approved
    );
    let mut wrong: Value = serde_json::from_slice(&fs::read(f.config())?)?;
    wrong["connector"]["account"] = json!("did:plc:other");
    fs::write(f.config(), serde_json::to_vec(&wrong)?)?;
    assert!(tangled_review::record_owner_decision(&f.state(), &f.config(), &input).is_err());
    Ok(())
}

#[test]
fn host_owner_interrupted_unpublished_temp_is_not_decision_authority() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    let history = f.review.state().join("owner-review-decisions");
    ladyshell::state::create_directory(&history)?;
    fs::write(history.join(".tmpABC123"), b"interrupted unpublished write")?;
    assert!(ladyshell::review_merge::check(&f.review.state(), &f.options()).is_err());
    let approved = tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?,
    )?;
    assert_eq!(
        ladyshell::review_merge::check(&f.review.state(), &f.options())?["human_review"],
        approved
    );
    // A call interrupted after immutable publication is already authoritative.
    let before = persistent_tree(&history)?;
    assert_eq!(
        tangled_review::record_owner_decision(
            &f.review.state(),
            &f.config,
            &owner_input(&f, "approved")?
        )?,
        approved
    );
    assert_eq!(persistent_tree(&history)?, before);
    Ok(())
}

struct OwnerFeedbackDelivery {
    bytes: Vec<u8>,
}
impl tangled_review::FeedbackDriver for OwnerFeedbackDelivery {
    fn deliver(&mut self, _: &Value, bytes: &[u8]) -> ladyshell::error::Result<()> {
        self.bytes = bytes.to_vec();
        Ok(())
    }
}
#[test]
fn host_owner_feedback_delivery_refuses_a_decision_changed_since_fetch() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    fs::write(
        f.review.state().join("state.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_name":"agent","sandbox_id":"bound-id","policy_hash":"policy","codex_binary":"/codex","owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"source","build_dir":"build","context":{"gateway":"test","workspace":"default"}}),
        )?,
    )?;
    tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?,
    )?;
    let mut driver = OwnerFeedbackDelivery { bytes: Vec::new() };
    let publication_path = f.review.state().join("publication.json");
    let original_publication = fs::read(&publication_path)?;
    let original_patches = f.review.data.lock().unwrap()["patches"].clone();
    let original_ticket = f.review.data.lock().unwrap()["ticket"].clone();
    for change in ["source_ahead", "superseded", "closed", "retargeted"] {
        let cached = tangled_review::feedback(&f.review.state(), &f.config)?;
        assert_eq!(cached["human_review"]["status"], "current");
        let journal_before = fs::read(f.review.state().join("review.json"))?;
        match change {
            "source_ahead" => {
                let mut publication: Value = serde_json::from_slice(&original_publication)?;
                publication["commit"] = json!("cccccccccccccccccccccccccccccccccccccccc");
                fs::write(&publication_path, serde_json::to_vec(&publication)?)?;
            }
            "superseded" => {
                let mut newer = original_patches[0].clone();
                newer["uri"] = json!("at://did:plc:repo/org.tangled.review.patch/newer");
                newer["cid"] = json!("newer-cid");
                newer["value"]["createdAt"] = json!("2026-11-05T00:00:02Z");
                f.review.data.lock().unwrap()["patches"]
                    .as_array_mut()
                    .ok_or("patches")?
                    .push(newer);
            }
            "closed" => f.review.data.lock().unwrap()["ticket"]["state"] = json!("closed"),
            _ => f.review.data.lock().unwrap()["ticket"]["targetBranch"] = json!("different"),
        }
        assert_eq!(
            fs::read(f.review.state().join("review.json"))?,
            journal_before
        );
        assert_eq!(
            tangled_review::status(&f.review.state(), &f.config)?["human_review"]["decision_id"],
            cached["human_review"]["decision_id"]
        );
        driver.bytes.clear();
        assert!(
            tangled_review::deliver_feedback_with(&f.review.state(), &mut driver).is_err(),
            "{change}"
        );
        assert!(driver.bytes.is_empty(), "{change}");
        let fresh = tangled_review::feedback(&f.review.state(), &f.config)?;
        assert_eq!(fresh["human_review"]["status"], "stale");
        assert_eq!(
            fresh["human_review"]["decision_id"],
            cached["human_review"]["decision_id"]
        );
        tangled_review::deliver_feedback_with(&f.review.state(), &mut driver)?;
        assert_eq!(serde_json::from_slice::<Value>(&driver.bytes)?, fresh);
        // Returning to current applicability cannot deliver the cached stale label.
        fs::write(&publication_path, &original_publication)?;
        f.review.data.lock().unwrap()["patches"] = original_patches.clone();
        f.review.data.lock().unwrap()["ticket"] = original_ticket.clone();
        driver.bytes.clear();
        assert!(
            tangled_review::deliver_feedback_with(&f.review.state(), &mut driver).is_err(),
            "stale-to-current {change}"
        );
        assert!(driver.bytes.is_empty());
    }
    tangled_review::feedback(&f.review.state(), &f.config)?;
    tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "withdrawn")?,
    )?;
    assert!(tangled_review::deliver_feedback_with(&f.review.state(), &mut driver).is_err());
    assert!(driver.bytes.is_empty());
    let fresh = tangled_review::feedback(&f.review.state(), &f.config)?;
    tangled_review::deliver_feedback_with(&f.review.state(), &mut driver)?;
    assert_eq!(serde_json::from_slice::<Value>(&driver.bytes)?, fresh);
    assert_eq!(fresh["human_review"]["decision"], "withdrawn");
    assert!(!String::from_utf8_lossy(&driver.bytes)
        .contains(f.review.root.path().to_str().ok_or("path")?));
    let context_path = f.review.state().join("review-feedback-owner-context.json");
    let binding = fs::read(&context_path)?;
    for damage in ["missing", "malformed", "different_hash", "project_config"] {
        match damage {
            "missing" => fs::remove_file(&context_path)?,
            "malformed" => fs::write(&context_path, b"{}")?,
            _ => {
                let mut context: Value = serde_json::from_slice(&binding)?;
                if damage == "different_hash" {
                    context["feedback_sha256"] = json!("different");
                } else {
                    context["config"] = json!(f.review.root.path().join("project/config.json"));
                    fs::copy(&f.config, f.review.root.path().join("project/config.json"))?;
                }
                fs::write(&context_path, serde_json::to_vec(&context)?)?;
            }
        }
        driver.bytes.clear();
        assert!(
            tangled_review::deliver_feedback_with(&f.review.state(), &mut driver).is_err(),
            "{damage}"
        );
        assert!(driver.bytes.is_empty());
        tangled_review::feedback(&f.review.state(), &f.config)?;
    }
    Ok(())
}

#[test]
fn host_owner_retry_retains_current_decision_identity_before_effect() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?,
    )?;
    let admission =
        tangled_review::merge_admission(&f.review.state(), &f.config, &f.head, &f.base)?;
    let policy = ladyshell::publication_policy::Policy::load(
        &f.policy,
        &f.review.root.path().join("project"),
    )?;
    let intent = json!({"schema_version":1,"project":f.review.root.path().join("project"),"export":f.export,"head":f.head,"expected_target":f.base,"reference":"refs/heads/main","destination":"git@127.0.0.1:did:plc:repo","confirmed":false,"review":admission,"review_config":f.config,"policy":f.policy,"policy_digests":policy.digests,"strategy":"signed_fast_forward"});
    fs::write(
        f.review.state().join("merge.json"),
        serde_json::to_vec(&intent)?,
    )?;
    tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "withdrawn")?,
    )?;
    let mut input = owner_input(&f, "approved")?;
    input.explanation = Some("A new explicit host decision".into());
    let current = tangled_review::record_owner_decision(&f.review.state(), &f.config, &input)?;
    let retried = ladyshell::review_merge::reconcile(&f.review.state(), true)?;
    assert_eq!(retried["confirmed"], true);
    assert_eq!(retried["review"]["review"]["human_review"], current);
    assert_eq!(
        fs::read_dir(f.review.state().join("merge-attempts"))?.count(),
        2
    );
    Ok(())
}

#[test]
fn host_owner_new_confirmed_round_with_same_code_requires_its_own_decision() -> Result {
    let f = MergeFixture::with_profile(true, true)?;
    let first = tangled_review::record_owner_decision(
        &f.review.state(),
        &f.config,
        &owner_input(&f, "approved")?,
    )?;
    let project = f.review.root.path().join("project");
    fixture_git(
        &project,
        &["commit", "-S", "--allow-empty", "-m", "New exact round"],
    )?;
    let head = fixture_git(&project, &["rev-parse", "HEAD"])?;
    let mut publication: Value =
        serde_json::from_slice(&fs::read(f.review.state().join("publication.json"))?)?;
    publication["commit"] = json!(head);
    fs::write(
        f.review.state().join("publication.json"),
        serde_json::to_vec(&publication)?,
    )?;
    let mut submission = f.review.input();
    submission.target_base = f.base.clone();
    submission.resubmit = true;
    submission.ticket_key = "79".into();
    f.review.data.lock().unwrap()["lost"] = json!(true);
    assert!(tangled_review::submit(&f.review.state(), &f.config, &submission).is_err());
    let pending = tangled_review::status(&f.review.state(), &f.config)?;
    assert_eq!(pending["display_state"], "recovery_needed");
    assert_eq!(pending["human_review"]["status"], "stale");
    let next = tangled_review::reconcile(&f.review.state(), &f.config)?;
    let status = tangled_review::status(&f.review.state(), &f.config)?;
    assert_eq!(status["human_review"]["status"], "stale");
    assert_eq!(status["human_review"]["decision_id"], first["decision_id"]);
    let mut options = f.options();
    options.head = &head;
    assert!(ladyshell::review_merge::check(&f.review.state(), &options).is_err());
    assert!(ladyshell::review_merge::run(&f.review.state(), &options).is_err());
    let input = serde_json::from_value(
        json!({"decision":"approved","head":head,"base":f.base,"patch_uri":next["patch"]["uri"],"patch_cid":next["patch"]["cid"]}),
    )?;
    let approved = tangled_review::record_owner_decision(&f.review.state(), &f.config, &input)?;
    assert_ne!(approved["decision_id"], first["decision_id"]);
    assert_eq!(
        ladyshell::review_merge::check(&f.review.state(), &options)?["human_review"],
        approved
    );
    assert_eq!(
        fs::read_dir(f.review.state().join("owner-review-decisions"))?.count(),
        2
    );
    Ok(())
}

#[test]
fn initial_ticket_refuses_predicted_key_without_remote_effect() -> Result {
    let f = Fixture::new(false)?;
    let mut input = f.input();
    input.ticket_key = "2".into();
    assert!(tangled_review::submit(&f.state(), &f.config(), &input).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 0);
    Ok(())
}
#[test]
fn allocated_ticket_canonical_readback_precedes_patch() -> Result {
    let f = Fixture::new(false)?;
    let receipt = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert_eq!(receipt["ticket_key"], "79");
    assert_eq!(receipt["ticket_allocation"], "server");
    assert_eq!(
        receipt["ticket_record"]["createdAt"],
        "2026-11-05T00:00:00Z"
    );
    assert_eq!(
        receipt["ticket"]["value"]["createdAt"],
        "2026-11-05T12:34:56.125Z"
    );
    assert_eq!(
        f.data.lock().map_err(|e| e.to_string())?["patches"][0]["value"]["ticket"],
        "79"
    );
    Ok(())
}

fn select_and_reconcile(f: &Fixture) -> Result<Value> {
    let pending = tangled_review::reconcile(&f.state(), &f.config())?;
    assert_eq!(pending["phase"], "ticket_pending");
    let candidate = &pending["ticket_candidates"][0];
    tangled_review::select_ticket(
        &f.state(),
        &f.config(),
        candidate["uri"].as_str().ok_or("uri")?,
        candidate["cid"].as_str().ok_or("cid")?,
    )?;
    Ok(tangled_review::reconcile(&f.state(), &f.config())?)
}
#[test]
fn unknown_ticket_requires_selection_and_never_repeats_create() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    for _ in 0..3 {
        let pending = tangled_review::reconcile(&f.state(), &f.config())?;
        assert_eq!(pending["phase"], "ticket_pending");
        assert_eq!(
            pending["ticket_candidates"]
                .as_array()
                .ok_or("candidates")?
                .len(),
            1
        );
        assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    }
    assert!(tangled_review::select_ticket(
        &f.state(),
        &f.config(),
        "at://did:plc:repo/org.tangled.track.ticket/79",
        "wrongcid"
    )
    .is_err());
    let receipt = select_and_reconcile(&f)?;
    assert_eq!(receipt["phase"], "submitted");
    assert!(receipt["ticket"]["x-tngl-change"].is_null());
    assert!(receipt["attestations"][0]["request"]["body"]["record"]["change"].is_null());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}
#[test]
fn ticket_candidates_refuse_changed_actor_prose_target_and_incomplete_listing() -> Result {
    for field in [
        "x-tngl-editor",
        "title",
        "body",
        "targetBranch",
        "createdAt",
    ] {
        let f = Fixture::new(false)?;
        typed_connector(&f, false)?;
        f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
        assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
        f.data.lock().map_err(|e| e.to_string())?["ticket"][field] = json!("changed");
        let pending = tangled_review::reconcile(&f.state(), &f.config())?;
        assert_eq!(pending["ticket_candidates"], json!([]), "{field}");
        assert!(tangled_review::select_ticket(
            &f.state(),
            &f.config(),
            "at://did:plc:repo/org.tangled.track.ticket/79",
            TICKET_CID
        )
        .is_err());
        assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    }
    let f = Fixture::new(false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    f.data.lock().map_err(|e| e.to_string())?["ticket_cursor"] = json!("same");
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    Ok(())
}
#[test]
fn unknown_new_ticket_abandonment_archives_before_pointer_removal() -> Result {
    let f = Fixture::new(false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let original = review_receipt(&f)?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["review", "abandon-ticket", "--state"])
        .arg(f.state())
        .arg("--config")
        .arg(f.config())
        .args([
            "--explanation",
            "Operator inspected read-back; remote effect remains unknown",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let abandoned: Value = serde_json::from_slice(&output.stdout)?;
    assert!(!f.state().join("review.json").exists());
    let path = f
        .state()
        .join("review-attempts")
        .join(original["attempt"].as_str().ok_or("attempt")?);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(path.join("intent.json"))?)?["attempt"],
        original["attempt"]
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(path.join("abandoned.json"))?)?,
        abandoned
    );
    assert!(f.state().join("publication.json").exists());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    Ok(())
}

#[test]
fn canonical_ticket_preserves_change_in_actor_pds_attestations() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    let receipt = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert_eq!(
        receipt["attestations"][0]["request"]["body"]["record"]["change"],
        "1111111111111111111111111111111111111111"
    );
    assert_eq!(
        receipt["attestations"][1]["request"]["body"]["record"]["change"],
        "2222222222222222222222222222222222222222"
    );
    Ok(())
}
#[test]
fn acknowledged_ticket_readback_strong_ref_failure_retains_known_identity() -> Result {
    let f = Fixture::new(false)?;
    f.data.lock().map_err(|e| e.to_string())?["readback_cid"] = json!("wrongcid");
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let pending = review_receipt(&f)?;
    assert_eq!(pending["phase"], "ticket_pending");
    assert_eq!(pending["ticket_response"]["cid"], TICKET_CID);
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    f.data
        .lock()
        .map_err(|e| e.to_string())?
        .as_object_mut()
        .ok_or("state")?
        .remove("readback_cid");
    let recovered = tangled_review::reconcile(&f.state(), &f.config())?;
    assert_eq!(recovered["phase"], "submitted");
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}
#[test]
fn ambiguous_ticket_candidates_require_explicit_identity_selection() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let record = f.data.lock().map_err(|e| e.to_string())?["ticket"].clone();
    f.data.lock().map_err(|e| e.to_string())?["extra_tickets"] = json!([{"uri":"at://did:plc:repo/org.tangled.track.ticket/80","cid":OTHER_TICKET_CID,"value":record}]);
    let pending = tangled_review::reconcile(&f.state(), &f.config())?;
    assert_eq!(
        pending["ticket_candidates"]
            .as_array()
            .ok_or("candidates")?
            .len(),
        2
    );
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["review", "select-ticket", "--state"])
        .arg(f.state())
        .arg("--config")
        .arg(f.config())
        .args([
            "--ticket-uri",
            "at://did:plc:repo/org.tangled.track.ticket/80",
            "--ticket-cid",
            OTHER_TICKET_CID,
        ])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let selected: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(selected["phase"], "patch_ready");
    assert_eq!(selected["ticket_key"], "80");
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    assert_eq!(
        tangled_review::reconcile(&f.state(), &f.config())?["phase"],
        "submitted"
    );
    assert_eq!(
        f.data.lock().map_err(|e| e.to_string())?["patches"][0]["value"]["ticket"],
        "80"
    );
    Ok(())
}
#[test]
fn legacy_fixed_key_pending_is_never_rewritten_or_resent() -> Result {
    let f = Fixture::new(false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let mut legacy = review_receipt(&f)?;
    legacy
        .as_object_mut()
        .ok_or("receipt")?
        .remove("ticket_allocation");
    legacy["ticket_key"] = json!("2");
    fs::write(f.state().join("review.json"), serde_json::to_vec(&legacy)?)?;
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(review_receipt(&f)?, legacy);
    legacy["phase"] = json!("ticket_ready");
    fs::write(f.state().join("review.json"), serde_json::to_vec(&legacy)?)?;
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    Ok(())
}

#[test]
fn abandonment_archive_conflict_preserves_pointer_and_replay_preserves_history() -> Result {
    let f = Fixture::new(false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let original = review_receipt(&f)?;
    let archive = f
        .state()
        .join("review-attempts")
        .join(original["attempt"].as_str().ok_or("attempt")?)
        .join("abandoned.json");
    fs::write(&archive, b"{}")?;
    assert!(tangled_review::abandon_ticket(&f.state(), &f.config(), "recorded evidence").is_err());
    assert_eq!(review_receipt(&f)?, original);
    fs::remove_file(&archive)?;
    let abandoned = tangled_review::abandon_ticket(&f.state(), &f.config(), "recorded evidence")?;
    // Simulate interruption after archive publication but before pointer removal.
    fs::write(
        f.state().join("review.json"),
        serde_json::to_vec(&original)?,
    )?;
    assert_eq!(
        tangled_review::abandon_ticket(&f.state(), &f.config(), "recorded evidence")?,
        abandoned
    );
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    Ok(())
}

#[test]
fn selected_ticket_pin_survives_restart_and_refuses_changed_record() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let selected = tangled_review::select_ticket(
        &f.state(),
        &f.config(),
        "at://did:plc:repo/org.tangled.track.ticket/79",
        TICKET_CID,
    )?;
    assert_eq!(review_receipt(&f)?, selected);
    f.data.lock().map_err(|e| e.to_string())?["readback_cid"] = json!(OTHER_TICKET_CID);
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    f.data
        .lock()
        .map_err(|e| e.to_string())?
        .as_object_mut()
        .ok_or("state")?
        .remove("readback_cid");
    assert_eq!(
        tangled_review::reconcile(&f.state(), &f.config())?["phase"],
        "submitted"
    );
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}

#[test]
fn unavailable_ticket_listing_retains_uncertainty_without_remote_retry() -> Result {
    let mut f = Fixture::new(false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let original = review_receipt(&f)?;
    f.stop.store(true, Ordering::Relaxed);
    if let Some(worker) = f.worker.take() {
        worker.join().map_err(|_| "fixture worker failed")?;
    }
    assert!(tangled_review::reconcile(&f.state(), &f.config()).is_err());
    assert_eq!(review_receipt(&f)?, original);
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 1);
    Ok(())
}

#[test]
fn accepted_server_extensions_are_not_exposed_in_retained_public_receipt() -> Result {
    let f = Fixture::new(false)?;
    let receipt = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    assert!(!receipt.to_string().contains("SECRET_PROVIDER_FIELD"));
    assert_eq!(receipt["phase"], "submitted");
    Ok(())
}

#[test]
fn malformed_shared_ticket_cids_refuse_selection_before_dependent_write() -> Result {
    let f = Fixture::new(false)?;
    typed_connector(&f, false)?;
    f.data.lock().map_err(|e| e.to_string())?["ticket_lost"] = json!(true);
    assert!(tangled_review::submit(&f.state(), &f.config(), &f.input()).is_err());
    let original = review_receipt(&f)?;
    for (case, cid) in [
        ("nonempty_fake", "ticketcid"),
        (
            "version",
            "bajyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "codec",
            "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "hash",
            "bafyrgiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "digest_length",
            "bafyrehyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "uppercase",
            "BAFYREIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "alphabet",
            "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0",
        ),
        (
            "truncated",
            "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "nonzero_padding",
            "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
        ),
        (
            "truncated_digest",
            "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "extra_digest",
            "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    ] {
        f.data.lock().map_err(|e| e.to_string())?["ticket_cid"] = json!(cid);
        assert!(
            tangled_review::select_ticket(
                &f.state(),
                &f.config(),
                "at://did:plc:repo/org.tangled.track.ticket/79",
                cid
            )
            .is_err(),
            "accepted {case}"
        );
        assert!(
            tangled_review::reconcile(&f.state(), &f.config()).is_err(),
            "discovered {case}"
        );
        assert_eq!(review_receipt(&f)?, original, "journal changed: {case}");
        assert_eq!(
            f.data.lock().map_err(|e| e.to_string())?["writes"],
            1,
            "dependent write: {case}"
        );
    }
    f.data.lock().map_err(|e| e.to_string())?["ticket_cid"] = json!(TICKET_CID);
    assert_eq!(select_and_reconcile(&f)?["phase"], "submitted");
    assert_eq!(f.data.lock().map_err(|e| e.to_string())?["writes"], 2);
    Ok(())
}
#[test]
fn record_cid_profile_accepts_distinct_arbitrary_sha256_digests() -> Result {
    for cid in [
        "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bafyreiabaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibae",
        "bafyreih777777777777777777777777777777777777777777777777774",
        "bafyreiaaaebagbafaydqqcikbmga2dqpcaireeyuculbogazdinryhi6d4",
    ] {
        let f = Fixture::new(false)?;
        f.data.lock().map_err(|e| e.to_string())?["ticket_cid"] = json!(cid);
        let receipt = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
        assert_eq!(receipt["ticket"]["cid"], cid);
        assert_eq!(receipt["phase"], "submitted");
    }
    Ok(())
}

#[path = "tangled_review/handoff.rs"]
mod handoff;

fn refreshable_connector(f: &Fixture) -> Result {
    typed_connector(f, false)?;
    let path = f.root.path().join("host.json");
    let mut host: Value = serde_json::from_slice(&fs::read(&path)?)?;
    host["schema_version"] = json!(2);
    host["session_policy"] = json!("refreshable");
    fs::write(path, serde_json::to_vec(&host)?)?;
    Ok(())
}
#[test]
fn refreshable_account_rebind_retains_attempt_and_refuses_policy_migration() -> Result {
    let f = Fixture::new(false)?;
    refreshable_connector(&f)?;
    let mut config: Value = serde_json::from_slice(&fs::read(f.config())?)?;
    config["require_owner_review"] = json!(true);
    fs::write(f.config(), serde_json::to_vec(&config)?)?;
    let first = tangled_review::submit(&f.state(), &f.config(), &f.input())?;
    let writes = connector_runtime(&f)?["writes"].clone();
    let decision = serde_json::from_value(
        json!({"decision":"approved","head":first["submitted_head"],"base":first["submitted_base"],"patch_uri":first["patch"]["uri"],"patch_cid":first["patch"]["cid"]}),
    )?;
    let approved = tangled_review::record_owner_decision(&f.state(), &f.config(), &decision)?;
    let mut runtime = connector_runtime(&f)?;
    runtime["observation_overrides"] = json!({"access_expired":true,"access_expires_at":1});
    store_connector_runtime(&f, &runtime)?;
    advance_credentials(&f, 2)?;
    let rebound = tangled_review::rebind_credentials(&f.state(), &f.config())?;
    assert_eq!(rebound["attempt"], first["attempt"]);
    assert_eq!(rebound["connector_authority"]["generation"], 1);
    assert_eq!(
        rebound["credential_history"][0]["authority"]["generation"],
        2
    );
    assert_eq!(connector_runtime(&f)?["writes"], writes);
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["human_review"],
        approved
    );
    f.publication("cccccccccccccccccccccccccccccccccccccccc")?;
    assert_eq!(
        tangled_review::status(&f.state(), &f.config())?["human_review"]["status"],
        "stale"
    );
    let legacy = Fixture::new(false)?;
    typed_connector(&legacy, false)?;
    tangled_review::submit(&legacy.state(), &legacy.config(), &legacy.input())?;
    let path = legacy.root.path().join("host.json");
    let mut host: Value = serde_json::from_slice(&fs::read(&path)?)?;
    host["schema_version"] = json!(2);
    host["session_policy"] = json!("refreshable");
    fs::write(path, serde_json::to_vec(&host)?)?;
    advance_credentials(&legacy, 2)?;
    assert!(tangled_review::rebind_credentials(&legacy.state(), &legacy.config()).is_err());
    Ok(())
}
#[test]
fn refreshable_account_rebind_refuses_mixed_unavailable_and_unknown_lifecycle() -> Result {
    for overrides in [
        json!({"schema_version":1}),
        json!({"schema_version":3}),
        json!({"session_policy":"bounded"}),
        json!({"lifecycle":"disconnected"}),
        json!({"lifecycle":"uncertain"}),
        json!({"lifecycle":"unknown"}),
        json!({"available":false}),
        json!({"uncertain_refresh":true}),
        json!({"lease_expired":false}),
        json!({"lease_expires_at":18446744073709551615_u64}),
        json!({"generation":8}),
        json!({"repository":"did:plc:other"}),
    ] {
        let f = Fixture::new(false)?;
        refreshable_connector(&f)?;
        tangled_review::submit(&f.state(), &f.config(), &f.input())?;
        advance_credentials(&f, 2)?;
        let mut runtime = connector_runtime(&f)?;
        let writes = runtime["writes"].clone();
        runtime["observation_overrides"] = overrides.clone();
        store_connector_runtime(&f, &runtime)?;
        assert!(
            tangled_review::rebind_credentials(&f.state(), &f.config()).is_err(),
            "{overrides}"
        );
        assert_eq!(connector_runtime(&f)?["writes"], writes);
    }
    Ok(())
}
