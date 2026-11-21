# ntpd-rs build dependency maintenance

Ladyboot uses ntpd-rs 1.9.0 from the pinned Nixpkgs revision. `ntpd-rs.nix`
keeps the pinned upstream release, default features and installation, replacing
dependency resolution with `ntpd-rs-Cargo.lock` and applying the single
`ntpd-rs-pin-endpoint.patch` source correction described below. These are security
and endpoint-policy corrections, not a dependency-count reduction. No Lady Cargo dependency is
added. The same native package is selected by minimal and debug images.

The upstream lock SHA256 is
`443db738db897f51ca18bcd8c185cf75a6a3b3f94ca41c30abc083c4ab1ff1ff`.
The retained corrected lock SHA256 is
`02776bae7f5c32ad00762d304025d4a5c1e761fb3d529e48af5a31f3ffc8153b`.
Its crates.io context remains 235 package names / 261 versions / 24 multiversion
families / 26 excess versions, including all target, build, test and optional
entries. These are this package's lock counts, not the image-wide closure delta.

| Package | Upstream lock | Retained lock | Reason |
| --- | --- | --- | --- |
| anyhow | 1.0.102 | 1.0.104 | RUSTSEC-2026-0190; reuse Lady's compatible version |
| crossbeam-epoch | 0.9.18 | 0.9.20 | RUSTSEC-2026-0204 |
| hickory-net/proto/resolver | 0.26.1 | 0.26.2 | DNS/DNSSEC advisory fixes |
| rustls | 0.23.40 | 0.23.46 | TLS advisory fixes; reuse Lady's compatible version |
| rustls-webpki | 0.103.13 | 0.103.16 | Distrusted intermediate handling; reuse Lady's compatible version |
| tokio | 1.52.3 | 1.53.3 | I/O soundness advisory fix |
| webpki-root-certs | 1.0.1 | 1.0.10 | emSign distrust update |
| aws-lc-rs | 1.17.0 | 1.19.0 | Compatible transitive resolution required by updated rustls |
| aws-lc-sys | 0.41.0 | 0.47.0 | Compatible transitive resolution; bundled AWS-LC 5.12.0 |

On 2026-11-18, OSV queries of every exact crates.io pair in the corrected lock,
with pagination exhausted, returned no advisory. The original lock matched nine
package identities. Maintainer repository advisories were checked separately:
ntpd-rs 1.9.0 is outside the seven published affected ranges; aws-lc-sys 0.47.0
and its bundled AWS-LC 5.12.0 are outside the published wrapper/native ranges.
This is a scoped check, not a vulnerability-free assertion. The optional
OpenSSL backend, other native code and the full compiler dependency closure do
not gain complete coverage from a crates.io query. Default AWS-LC/RustCrypto
features are preserved; no FIPS or OpenSSL backend is selected by this recipe.

Source provenance and dated results live in the sibling Nickeling report:
`docs/bootc-podman/2026-11-15/security/ntpd-rs-{candidate,corrected,native}-advisories.json`.
The maintained OSV collection recipe is `check-cargo-advisories.py` there.
Run it against the retained lock after every change and compare exact identity
sets. Independent distribution must package these reports/recipes explicitly.

Nixpkgs builds with Rust/Cargo 1.99.0. The host workspace uses 1.99.1; these
are different toolchains. The 1.99.1 release fixes an x86_64 FFI boolean-return
miscompilation as well as other regressions. No compiler-security clearance is
inferred from the package audit; this native compiler difference remains visible.
Do not silently switch Nixpkgs or use a host rustup compiler in the Nix build.

One additional upstream test, `daemon::spawn::nts::tests::direct_name_resolution`,
binds `[::]:0` and fails with EAFNOSUPPORT in the native Nix sandbox. It is
explicitly excluded without enabling IPv6 or weakening isolation. The target is
IPv4; direct-name resolution and NTS are tested in the isolated fixture.

The inherited Nixpkgs recipe skips 19 upstream tests because its bundled TLS
certificates have timestamp issues. Their names remain in the pinned recipe.
The package build cannot establish the omitted NTS roundtrips passed. Ladyboot's
isolated NTS qualification must cover its actual trust/hostname/time policy;
never bypass certificate validity to make a test pass.

Owner: Ladyboot native-image maintainers. Cost: one corrected lock, exact-version
advisory refresh and native rebuild/qualification on changes. Review deadline:
2026-12-18 or the next upstream ntpd-rs release, whichever occurs first. Return to
the pinned upstream recipe once its resolved lock incorporates the fixes and
passes the same checks; do not automatically renew this deviation.

Primary sources:

- https://github.com/pendulum-project/ntpd-rs/security/advisories
- https://github.com/aws/aws-lc-rs/security/advisories
- https://github.com/aws/aws-lc/security/advisories
- https://github.com/aws/aws-lc-rs/releases/tag/v1.19.0
- https://blog.rust-lang.org/2026/10/15/Rust-1.99.1/

## Negotiated endpoint policy correction

The upstream client follows the NTP address/port advertised by authenticated
NTS-KE. The global firewall also permits other protocols, including DNS; its
port grants alone cannot prove the NTS client stays on the declared IP:123.
The bounded native patch adds optional `expected-ntp-address` to a source and
rejects a different resolved SocketAddr BEFORE creating its NTP source. TLS
validation and crypto are unchanged. Ladyboot always generates the pin for each
source. Unpinned upstream configurations keep their original semantics; they
are not generated or supported by the Ladyboot profile.

Tests cover the matching endpoint, wrong IP, DNS/KE/other ports, loopback and
IPv6; the native configuration parser and real negotiated address/port refusals
are separate gates. This is maintained native source divergence: two upstream
files, a single optional field, one equality guard, and its tests. It adds no
dependency, changes no public Nickel profile shape and is not a crypto fork.
The same maintainers/deadline above apply. Additional cost: rebase and review
this patch on each ntpd-rs update. Remove it when upstream provides equivalent
per-source endpoint pinning and the same rejection tests pass. No upstream
submission or acceptance is claimed.

The recipe sets `CARGO_PROFILE_RELEASE_DEBUG=0` instead of upstream's `debug=2`
to avoid bulky disposable debug objects during native builds/tests. Release
optimization, LTO, feature selection and assertions are unchanged; Nix strips
the delivered executables. This is not a dependency-count reduction or a new
production/debug behavior split. Native build and runtime checks still apply.
