"""Boot an unpacked image in a disposable VM; this does not test bootc install."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--mkfs", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=600, help="Wall-clock deadline for the TCG VM in seconds")
    args = parser.parse_args()
    kernels = list((args.rootfs / "usr/lib/modules").glob("*/vmlinuz"))
    if len(kernels) != 1:
        parser.error("Expected exactly one kernel in the built rootfs")
    args.report.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="ladyboot-boot-") as temporary:
        disk = Path(temporary) / "root.ext4"
        with disk.open("xb") as handle:
            handle.truncate(4 * 1024**3)
        with (args.report / "mkfs.log").open("x") as log:
            subprocess.run(
                [args.mkfs, "-F", "-L", "ladyboot", "-d", str(args.rootfs), str(disk)],
                stdout=log, stderr=subprocess.STDOUT, timeout=180, check=True,
            )
        command = [
            args.qemu, "-machine", "q35,accel=tcg", "-cpu", "max", "-smp", "2",
            "-m", "2048", "-nographic", "-no-reboot", "-monitor", "none",
            "-kernel", str(kernels[0]), "-initrd", str(kernels[0].parent / "initramfs.img"),
            "-append", "root=/dev/sda console=ttyS0 panic=1 systemd.show_status=1",
            "-device", "virtio-scsi-pci,id=scsi0",
            "-drive", f"file={disk},format=raw,if=none,id=rootdisk",
            "-device", "scsi-hd,drive=rootdisk,bus=scsi0.0",
            "-nic", "user,model=virtio-net-pci",
            "-device", "virtio-rng-pci",
            "-device", "virtio-balloon-pci",
            "-device", "virtio-serial-pci",
            "-chardev", f"socket,path={args.report / 'agent.sock'},server=on,wait=off,id=agent",
            "-device", "virtserialport,chardev=agent,name=org.qemu.guest_agent.0",
        ]
        (args.report / "command.json").write_text(json.dumps(command, indent=2) + "\n")
        with (args.report / "serial.log").open("x") as log:
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + args.timeout
            try:
                while process.poll() is None:
                    output = (args.report / "serial.log").read_text(errors="replace")
                    if "LADYBOOT_INIT_FAILED" in output or "Kernel panic" in output:
                        raise RuntimeError(f"Guest failed during boot; inspect {args.report / 'serial.log'}")
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Guest boot deadline exceeded; inspect {args.report / 'serial.log'}")
                    time.sleep(0.25)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
        output = (args.report / "serial.log").read_text(errors="replace")
        if process.returncode != 0 or "LADYBOOT_BOOT_OK" not in output:
            raise SystemExit(f"Boot test failed; inspect {args.report / 'serial.log'}")
        print("Booted the Nix-assembled rootfs and ran bootc under systemd.")
        print("Bootc installation, bootloader boot and updates are still unverified.")


if __name__ == "__main__":
    main()
