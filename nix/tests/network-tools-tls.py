"""Qualify installed network clients against synthetic loopback HTTPS endpoints."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import threading


def assert_tls_refusal(tool, case, result):
    # libcurl's OpenSSL backend supplies the same reason to all three clients.
    pattern = ((r"SSL certificate (?:problem: self-signed certificate|"
                r"OpenSSL verify result: self-signed certificate \(18\))")
               if case == "wrong-ca" else r"certificate subject name")
    if tool == "cargo":
        if "[60]" not in result.stderr:
            raise AssertionError((tool, case, "missing certificate verification error"))
    if not re.search(pattern, result.stderr, re.IGNORECASE):
        raise AssertionError((tool, case, "unexpected refusal reason"))
    if result.stdout:
        raise AssertionError((tool, case, "stdout delivered despite TLS refusal"))


def main():
    parser = argparse.ArgumentParser()
    for name in ("git", "curl", "curl-lib", "openssl", "openssl-lib", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--cargo")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir()
    work = Path.cwd()
    home = work / "home"
    home.mkdir()
    env = {
        "PATH": os.environ["PATH"], "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"), "LC_ALL": "C", "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": "0",
        "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
        "NO_PROXY": "*", "no_proxy": "*",
    }

    def run(name, command, debug=False, extra_env=None):
        result = subprocess.run(command, env=env | (extra_env or {}) | ({"LD_DEBUG": "libs"} if debug else {}),
                                capture_output=True, text=True, timeout=40)
        (output / (name + ".stdout")).write_text(result.stdout)
        (output / (name + ".stderr")).write_text(result.stderr)
        return result

    def success(name, command):
        result = run(name, command)
        if result.returncode:
            raise AssertionError((name, result.returncode, result.stderr))
        return result.stdout

    for name in ("server", "untrusted"):
        success("certificate-" + name,
                [args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
                 "-days", "1", "-subj", "/CN=localhost", "-addext",
                 "subjectAltName=DNS:localhost", "-keyout", name + ".key",
                 "-out", name + ".pem"])
    served = work / "served"
    served.mkdir()
    payload = "lady-network-tools\n"
    (served / "payload.txt").write_text(payload)
    source = work / "source"
    success("git-init", [args.git, "init", str(source)])
    (source / "payload.txt").write_text(payload)
    success("git-add", [args.git, "-C", str(source), "add", "payload.txt"])
    success("git-commit", [args.git, "-C", str(source), "-c", "user.name=Fixture",
                           "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Fixture"])
    expected_head = success("git-head", [args.git, "-C", str(source), "rev-parse", "HEAD"]).strip()
    bare = served / "repo.git"
    success("git-bare", [args.git, "clone", "--bare", "--no-hardlinks", str(source), str(bare)])
    success("git-server-info", [args.git, "--git-dir", str(bare), "update-server-info"])
    requests = []

    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, pattern, *values):
            requests.append({"path": self.path, "message": pattern % values})

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=str(served)))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("server.pem", "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    if args.cargo:
        (served / "index").mkdir()
        (served / "index/config.json").write_text(json.dumps({
            "dl": f"https://localhost:{port}/crates",
            "api": f"https://localhost:{port}",
        }))
        (served / "api/v1").mkdir(parents=True)
        (served / "api/v1/crates").write_text(json.dumps({
            "crates": [{"id": "lady-network-probe", "name": "lady-network-probe",
                        "max_version": "0.1.0", "description": "TLS fixture"}],
            "meta": {"total": 1},
        }))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    expected_libraries = {
        str((Path(args.openssl_lib) / "libssl.so.3").resolve()),
        str((Path(args.openssl_lib) / "libcrypto.so.3").resolve()),
        str((Path(args.curl_lib) / "libcurl.so.4").resolve()),
    }
    records = []
    try:
        for name, host, ca in [("trusted", "localhost", "server.pem"),
                               ("wrong-ca", "localhost", "untrusted.pem"),
                               ("wrong-name", "127.0.0.1", "server.pem")]:
            # A successful request immediately before each refusal distinguishes
            # verification failures from a stopped or unreachable server.
            ready = run("ready-" + name,
                        [args.curl, "--disable", "--silent", "--show-error", "--noproxy", "*",
                         "--proto", "=https", "--max-time", "10", "--cacert", "server.pem",
                         f"https://localhost:{port}/payload.txt"])
            if ready.returncode or ready.stdout != payload:
                raise AssertionError((name, "HTTPS server unavailable", ready.stderr))
            for tool in (("curl", "git", "cargo") if args.cargo else ("curl", "git")):
                url = f"https://{host}:{port}"
                destination = work / ("clone-" + name)
                if tool == "curl":
                    command = [args.curl, "--disable", "--silent", "--show-error", "--noproxy", "*",
                               "--proto", "=https", "--max-time", "10", "--cacert", ca,
                               url + "/payload.txt"]
                elif tool == "git":
                    command = [args.git, "-c", "http.proxy=", "-c", "http.sslVerify=true",
                               "-c", "http.sslCAInfo=" + str(work / ca), "clone", "--quiet",
                               "--no-checkout", url + "/repo.git", str(destination)]
                else:
                    # Keep Cargo's default HTTP TLS verification; ssl-verify
                    # is no longer a supported key. Exercise both refusals.
                    command = [args.cargo, "--config", 'http.proxy=""',
                               "--config", "net.retry=0",
                               "search", "lady-network-probe", "--index",
                               "sparse+" + url + "/index/", "--limit", "1"]
                extra_env = {} if tool != "cargo" else {
                    "CARGO_HOME": str(work / ("cargo-home-" + name)),
                    "RUSTUP_HOME": str(home / "rustup"),
                    "CARGO_HTTP_CAINFO": str(work / ca),
                    "CARGO_HTTP_TIMEOUT": "10",
                }
                result = run(tool + "-" + name, command, debug=True, extra_env=extra_env)
                if tool == "cargo" and "warning: unused config key" in result.stderr:
                    raise AssertionError((tool, name, "unused fixture configuration"))
                expected_exit = 0 if name == "trusted" else {"curl": 60, "git": 128, "cargo": 101}[tool]
                if result.returncode != expected_exit:
                    raise AssertionError((tool, name, result.returncode, expected_exit))
                loaded = {str(Path(path).resolve()) for path in
                          re.findall(r"calling init:\s+(\S+)", result.stderr)
                          if Path(path).name in ("libssl.so.3", "libcrypto.so.3", "libcurl.so.4")}
                if loaded != expected_libraries:
                    raise AssertionError((tool, name, "unexpected libraries", loaded, expected_libraries))
                if name == "trusted":
                    if tool == "curl" and result.stdout != payload:
                        raise AssertionError("curl payload differs")
                    if tool == "git":
                        head = success("cloned-head", [args.git, "-C", str(destination), "rev-parse", "HEAD"])
                        content = success("cloned-content", [args.git, "-C", str(destination), "show", "HEAD:payload.txt"])
                        if head.strip() != expected_head or content != payload:
                            raise AssertionError("Git clone payload or commit differs")
                    if tool == "cargo":
                        if not re.search(r'^lady-network-probe = "0\.1\.0"', result.stdout, re.MULTILINE):
                            raise AssertionError("Cargo registry search payload differs")
                        if not any(item["path"].split("?", 1)[0] == "/api/v1/crates" for item in requests):
                            raise AssertionError("Cargo did not query the local registry API")
                else:
                    assert_tls_refusal(tool, name, result)
                    if tool == "git" and destination.exists():
                        raise AssertionError((name, "failed clone left a destination"))
                records.append({"tool": tool, "case": name, "exit": result.returncode,
                                "loaded_libraries": sorted(loaded)})
        (output / "results.json").write_text(json.dumps(records, indent=2) + "\n")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (output / "requests.json").write_text(json.dumps(requests, indent=2) + "\n")


if __name__ == "__main__":
    main()
