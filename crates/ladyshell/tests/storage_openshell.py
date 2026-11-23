"""Fixed synthetic cap probe; invoked only by storage_openshell.rs qualification."""
import errno
import json
import os

ROOTS = ["/var/lib/ladyshell/broker/" + area for area in ("control", "artifacts", "incoming")]
# The cap must not be bypassed through the image's otherwise writable /tmp.
path = "/tmp/.ladyshell-cap-probe-" + str(os.getpid())
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EPERM), error
else:
    os.close(fd)
    os.unlink(path)
    raise AssertionError("unbounded /tmp is writable")

observations = []
for root in ROOTS:
    owner = os.stat(root, follow_symlinks=False)
    assert owner.st_uid == 10001 and owner.st_gid == 10001
    assert owner.st_mode & 0o777 == 0o700
    stat = os.statvfs(root)
    total = stat.f_blocks * stat.f_frsize
    assert 4096 <= total <= 262144 and 16 <= stat.f_files <= 128
    assert stat.f_flag & os.ST_NOSUID and stat.f_flag & os.ST_NODEV
    observations.append(dict(target=root, device=owner.st_dev, bytes=total,
        available_bytes=stat.f_bavail * stat.f_frsize,
        inodes=stat.f_files, available_inodes=stat.f_favail))
    path = root + "/.qualification-bytes"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    full = False
    try:
        try:
            for _ in range(total // 4096 + 2):
                assert os.write(fd, b"x" * 4096) > 0
            os.fsync(fd)
        except OSError as error:
            assert error.errno == errno.ENOSPC, error
            full = True
    finally:
        os.close(fd)
        os.unlink(path)
    assert full, "byte hard cap did not reject a write"
    created = []
    full = False
    try:
        try:
            for index in range(stat.f_files + 2):
                path = root + "/.qualification-inode-" + str(index)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                created.append(path)
        except OSError as error:
            assert error.errno == errno.ENOSPC, error
            full = True
    finally:
        for path in created:
            os.unlink(path)
    assert full, "inode hard cap did not reject creation"
    after = os.statvfs(root)
    assert after.f_bavail == stat.f_bavail and after.f_favail == stat.f_favail
print(json.dumps(observations))
