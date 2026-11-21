#!/usr/bin/sh
# Disposable test orchestrator injected into /var after bootc installation.
# The installed OS is the production archive, without a Python test overlay.
set -eu
export PATH=/usr/bin
state=/var/lib/ladyboot-qualification
phase=$(cat "$state/phase")
finish() {
    code=$?
    trap - EXIT
    if [ "$code" -ne 0 ]; then
        echo "LADYBOOT_LIFECYCLE_FAILED phase=$phase exit=$code"
        journalctl -b --no-pager -n 100 || true
    fi
    systemctl poweroff --no-block
    exit "$code"
}
trap finish EXIT
status() {
    echo "LADYBOOT_STATUS_BEGIN $1"
    bootc status --json
    echo LADYBOOT_STATUS_END
}
rootless() {
    setpriv --reuid=1000 --regid=1000 --init-groups env -i \
        USER=containers LOGNAME=containers HOME=/var/home/containers \
        XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
        PATH=/usr/bin podman "$@"
}
observe() {
    . /etc/os-release
    echo "LADYBOOT_OBSERVATION phase=$phase version=$VERSION_ID machine=$(cat /etc/machine-id) home_uid=$(stat -c %u /var/home/containers)"
    cat /proc/cmdline
    test -d /sys/firmware/efi
    test -f /run/ostree-booted
    status booted
}
persist() {
    test "$(cat /etc/machine-id)" = "$(cat "$state/machine-id")"
    test "$(cat /etc/ladyboot-lifecycle.conf)" = 'retained-local-configuration'
    test "$(stat -c %u /var/home/containers)" = 1000
    test "$(readlink /etc/systemd/user-generators/podman-user-generator)" = "$state/podman-user-generator"
    sha256sum -c "$state/accounts.sha256"
    rootless image exists localhost/ladyboot-smoke:1
    rootless run --rm --pull=never --network=none --cap-drop=all \
        -v lifecycle-data:/data localhost/ladyboot-smoke:1 \
        /bin/sh -ec 'test "$(cat /data/marker)" = persistent-volume'
}

echo "LADYBOOT_PHASE $phase"
observe
case "$phase" in
    prepare)
        test "$VERSION_ID" = 1
        systemctl is-active ladyboot-podman-init.service user@1000.service
        rootless load --input "$state/smoke.tar.gz"
        rootless volume create lifecycle-data
        rootless run --rm --pull=never --network=none --cap-drop=all \
            -v lifecycle-data:/data localhost/ladyboot-smoke:1 \
            /bin/sh -ec 'echo persistent-volume > /data/marker'
        cp /etc/machine-id "$state/machine-id"
        echo retained-local-configuration > /etc/ladyboot-lifecycle.conf
        sha256sum /etc/passwd /etc/group /etc/subuid /etc/subgid > "$state/accounts.sha256"
        printf '#!/usr/bin/sh\nexec /usr/lib/systemd/user-generators/podman-user-generator "$@"\n' > "$state/podman-user-generator"
        chmod 755 "$state/podman-user-generator"
        ln -sfn "$state/podman-user-generator" /etc/systemd/user-generators/podman-user-generator
        # Interrupted image transfer: reject a truncated archive before staging.
        head -c 65536 "$state/os-v2.oci.tar" > "$state/current.oci.tar.partial"
        mv "$state/current.oci.tar.partial" "$state/current.oci.tar"
        if bootc upgrade > "$state/truncated-upgrade.log" 2>&1; then
            echo 'Unexpectedly accepted truncated OS archive'
            exit 1
        fi
        cat "$state/truncated-upgrade.log"
        status rejected-truncated-image
        echo recover > "$state/phase"
        ;;
    recover)
        test "$VERSION_ID" = 1
        persist
        cp "$state/os-v2.oci.tar" "$state/current.oci.tar.complete"
        mv "$state/current.oci.tar.complete" "$state/current.oci.tar"
        bootc upgrade --check
        status metadata-only
        echo stage > "$state/phase"
        ;;
    stage)
        test "$VERSION_ID" = 1
        persist
        bootc upgrade
        status staged-update
        echo updated > "$state/phase"
        ;;
    updated)
        test "$VERSION_ID" = 2
        persist
        bootc rollback
        status rollback-queued
        echo rolled-back > "$state/phase"
        ;;
    rolled-back)
        test "$VERSION_ID" = 1
        persist
        # A retained local identity disagreement must not be adopted on reboot.
        sed 's/^containers:x:1000:1000:/containers:x:1001:1000:/' /etc/passwd > "$state/passwd-conflict"
        test "$(grep -c '^containers:x:1001:1000:' "$state/passwd-conflict")" = 1
        cat "$state/passwd-conflict" > /etc/passwd
        echo collision > "$state/phase"
        ;;
    collision)
        test "$VERSION_ID" = 1
        test "$(systemctl is-failed ladyboot-podman-init.service || true)" = failed
        test "$(stat -c %u /var/home/containers)" = 1000
        test "$(stat -c %u /var/home/containers/.local/share/containers/storage/volumes/lifecycle-data/_data/marker)" = 1000
        test "$(grep -c '^containers:x:1001:1000:' /etc/passwd)" = 1
        test "$(cat /etc/machine-id)" = "$(cat "$state/machine-id")"
        echo LADYBOOT_LIFECYCLE_OK
        ;;
    *) echo 'Unexpected test phase'; exit 1 ;;
esac
sync
echo "LADYBOOT_PHASE_OK $phase"
