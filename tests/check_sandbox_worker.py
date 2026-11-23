"""Exercise the independent worker contract without any application framework."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=Path)
    args = parser.parse_args()
    base = Path("/tmp/lady")
    base.mkdir(exist_ok=True)
    assert not base.is_symlink() and base.stat().st_uid == os.getuid()
    with tempfile.TemporaryDirectory(prefix="worker-contract-", dir=base) as directory:
        roots = [Path(directory) / name for name in ("control", "artifacts", "incoming")]
        for root in roots:
            root.mkdir(mode=0o700)

        def call(mode, value, *extra, success=True):
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            result = subprocess.run([str(args.worker.resolve()), mode, *map(str, roots), *extra],
                                    input=data, capture_output=True, timeout=10, env={})
            assert (result.returncode == 0) == success, (mode, result)
            return json.loads(result.stdout) if success else None

        probe = {"format": 1, "action": "probe"}
        assert call("sandbox-control", probe) == {"format": 1, "protocol": "ladyshell-worker-v1"}
        original = {"key": "b" * 64, "value": {"independent": True}}
        call("sandbox-execute", original, success=False)
        init = {"format": 1, "action": "initialize", "token": "a" * 64}
        assert call("sandbox-control", init)["accepting"] is True
        marker = roots[0] / ".lifecycle/open"
        held = marker.with_name("held")
        marker.rename(held)
        marker.write_text("not a directory")
        call("sandbox-control", init, success=False)
        marker.unlink()
        marker.symlink_to(held)
        call("sandbox-control", init, success=False)
        marker.unlink()
        held.rename(marker)
        call("sandbox-control", {**init, "extra": True}, success=False)
        call("sandbox-control", {**init, "format": 2}, success=False)
        assert call("sandbox-execute", original) == {"echo": original["value"]}
        call("sandbox-execute", original, success=False)
        assert call("sandbox-observe", original) == {"echo": original["value"]}
        call("sandbox-observe", {**original, "value": "changed"}, success=False)
        call("sandbox-observe", {"key": "c" * 64, "value": "absent"}, success=False)
        assert not (roots[0] / ("c" * 64 + ".json")).exists()
        payload = b"content independent of any component format"
        digest = hashlib.sha256(payload).hexdigest()
        assert call("sandbox-upload", payload, digest) == {"Ok": {"component": digest, "bytes": len(payload)}}
        call("sandbox-upload", payload, digest, success=False)
        call("sandbox-upload", b"changed", digest, success=False)
        assert (roots[2] / (digest + ".wasm")).read_bytes() == payload
        seal = {**init, "action": "seal"}
        guard = os.open(roots[0], os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(guard, fcntl.LOCK_SH | fcntl.LOCK_NB)
            call("sandbox-control", seal, success=False)
            assert (roots[0] / ".lifecycle/open").is_dir()
        finally:
            os.close(guard)
        assert call("sandbox-control", seal)["accepting"] is False
        assert call("sandbox-control", init)["accepting"] is False
        assert call("sandbox-control", seal)["accepting"] is False
        call("sandbox-execute", {"key": "d" * 64, "value": "after seal"}, success=False)
        data = b"after seal"
        call("sandbox-upload", data, hashlib.sha256(data).hexdigest(), success=False)
        assert call("sandbox-observe", original) == {"echo": original["value"]}
        call("sandbox-control", b" " * 16385, success=False)
        roots = [Path(directory) / ("interrupted-" + name) for name in ("control", "artifacts", "incoming")]
        for root in roots:
            root.mkdir(mode=0o700)
        (roots[0] / ".lifecycle").mkdir(mode=0o700)
        assert call("sandbox-control", init)["accepting"] is False
        assert not (roots[0] / ".lifecycle/open").exists()
        print("Independent worker: bounded transport, original-only observation, create-only intake, busy seal and irreversible sealing passed.")


if __name__ == "__main__":
    main()
