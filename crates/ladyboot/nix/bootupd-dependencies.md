# bootupd build dependency provenance

Owner: Ladyboot maintainers. Scope: native bootloader tool only; no project Rust
manifest or existing lockfile changes. Upstream source 0.3.2 is unmodified.
Source: https://github.com/coreos/bootupd/releases/tag/v0.3.2
Full tag archive: https://codeload.github.com/coreos/bootupd/tar.gz/refs/tags/v0.3.2
SHA-256: 7323519fb230d0508e6a9ccbd65763d735fd6af713725aead6c3f015544c48fe.
The initially audited release crate (SHA-256
4d98e0e799c53340069f6793c58bbee75c1cd321c19ffca35e5b18ea592682f4)
omits test fixtures and cannot compile its tests. All src/ files were compared
byte-for-byte to the complete tag archive and are identical.

The upstream release lock and upstream main c9808ed12197c6fd7209b2411342b4fa01f35b4f
both contained affected versions. The retained build lock applies cargo update
--precise for rand 0.8.6 and 0.9.3 (RUSTSEC-2026-0097), rustix 1.1.6
(RUSTSEC-2026-0486), and tokio 1.51.6 (RUSTSEC-2026-0386).
Cargo additionally resolves libc 0.2.191, mio 1.2.5 and tokio-macros 2.7.2.
No package additions/removals: 205 packages, 19 multiversion families and 21
excess versions before and after. This is not a dependency reduction.

cargo-audit 0.22.2, RustSec database commit
4ef2df8e806a65e2f1ecc14f56f51249062b23d6 (1509 advisories,
updated 2026-11-13T13:33:03+01:00), checked 2026-11-15:
upstream release has four unsound warnings; corrected lock has no vulnerabilities
or warnings reported. This does not cover native libraries or the whole OS.

Reproduction: fetch the complete v0.3.2 tag archive from the URL above and
verify SHA-256 7323519fb230d0508e6a9ccbd65763d735fd6af713725aead6c3f015544c48fe.
Run the four precise Cargo updates above sequentially, compare the full lock,
then run cargo-audit against that lock with a current database. Nix uses the retained lock and runs upstream
unit tests; VM installation/update tests are separately required.

Maintenance cost: one additional upstream build recipe, one scoped 205-package
lock and upstream/VM validation on updates. Replace this lock override with an
upstream audited release as soon as it includes these fixes; review by
2026-12-15. No upstream source fork is introduced.

Nix test coverage: the complete source compiles; 36 unit tests passed, one
upstream ignored test, and test_get_product_name failed because /etc/os-release
is absent in the sandbox. The recipe now skips only that host-identity test;
its product-name lookup must be covered by the installation VM, still pending.
No sandbox access is widened and no upstream source test is patched.
