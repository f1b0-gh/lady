"""Exercise the installed curl against a local OpenSSL TLS server."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--curl", required=True)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--openssl-lib", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir()
    work = Path.cwd()
    (work / "index.html").write_text("lady-tpm-native-tls\n")
    for name in ("server", "untrusted"):
        result = subprocess.run(
            [args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc",
             "-days", "1", "-subj", "/CN=localhost", "-addext",
             "subjectAltName=DNS:localhost", "-keyout", name + ".key",
             "-out", name + ".pem"],
            capture_output=True, timeout=30,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with (output / "server.log").open("wb") as server_log:
        server = subprocess.Popen(
            [args.openssl, "s_server", "-accept", f"127.0.0.1:{port}",
             "-cert", "server.pem", "-key", "server.key", "-WWW", "-quiet"],
            stdout=server_log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                if server.poll() is not None:
                    raise RuntimeError("TLS server exited before readiness")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("TLS server did not become ready") from None
                    time.sleep(0.05)
            records = []
            cases = [("trusted", "localhost", "server.pem", 0),
                     ("wrong-ca", "localhost", "untrusted.pem", 60),
                     ("wrong-name", "127.0.0.1", "server.pem", 60)]
            expected_libraries = {
                str(Path(args.openssl_lib) / "libssl.so.3"),
                str(Path(args.openssl_lib) / "libcrypto.so.3"),
            }
            for name, host, ca, expected_exit in cases:
                command = [args.curl, "--silent", "--show-error", "--noproxy", "*",
                           "--proto", "=https", "--max-time", "10", "--cacert", ca,
                           "--resolve", f"localhost:{port}:127.0.0.1",
                           f"https://{host}:{port}/index.html"]
                result = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                        env={**os.environ, "LD_DEBUG": "libs"})
                (output / (name + ".stdout")).write_text(result.stdout)
                (output / (name + ".stderr")).write_text(result.stderr)
                loaded = {str(Path(path).resolve()) for path in
                          re.findall(r"calling init:\s+(\S+)", result.stderr)
                          if Path(path).name in ("libcrypto.so.3", "libssl.so.3")}
                expected = {str(Path(path).resolve()) for path in expected_libraries}
                if loaded != expected:
                    raise AssertionError((name, "unexpected native libraries", loaded, expected))
                if result.returncode != expected_exit:
                    raise AssertionError((name, result.returncode, expected_exit))
                if expected_exit == 0 and result.stdout.strip() != "lady-tpm-native-tls":
                    raise AssertionError((name, "unexpected TLS response", result.stdout))
                if expected_exit != 0 and result.stdout:
                    raise AssertionError((name, "body delivered despite certificate refusal"))
                records.append({"name": name, "exit": result.returncode,
                                "loaded_libraries": sorted(loaded)})
            (output / "results.json").write_text(json.dumps(records, indent=2) + "\n")
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    main()
