# Public synthetic TLS fixture

This private key is deliberately public test data, generated solely for the
isolated QEMU peer. Never use it for a deployment or add its certificate to a
production trust store. Only the peer fixture receives the key; the DUT and
its probe container receive the certificate explicitly for these tests.

Inputs were generated with OpenSSL 3.0.13 (2024-01-30):

```sh
openssl req -x509 -newkey rsa:2048 -noenc -days 36500 \
  -subj '/CN=probe.test/O=Ladyboot synthetic fixture only' \
  -addext 'subjectAltName=DNS:probe.test,IP:192.0.2.2,IP:192.0.2.3' \
  -keyout net-key.pem -out net-cert.pem
```

The retained files are the exact rebuild inputs. Regenerating creates a new key
and validity window; it is not a bit-for-bit reproduction of these inputs.

## NTS refusal fixtures

`nts/` contains a separate public CA, public synthetic server key and four
certificates: valid `nts.test`, wrong `other.test` identity, expired (2025), and
not valid before 2090. No production image contains these files. Only the peer
receives the key. The DUT receives the CA explicitly; the unknown-CA case uses
only the production bundle. [`generate-nts-certificates.py`](../../generate-nts-certificates.py) uses cryptography
41.0.7 for initial generation with fixed validity dates; retained PEM files are
the exact rebuild inputs. Regeneration changes keys/serials intentionally.

The isolated QEMU driver fixes both guest RTC bases to 2026-11-18T12:00:00 with
`clock=vm`; it never changes the host clock. Their start times may differ, within
the 1800-second production correction limit. A future fixture RTC change must
review certificate validity cases. Production certificate/time checks remain on.

The real peer implementation is pinned Nixpkgs chrony 4.9, solely in the test
rootfs, started with `-x` (no clock adjustment) and a local stratum-1 source.
Production uses ntpd-rs only. Native code and crypto are not implemented by the
Python fixture. The old plain 48-byte NTP response generator is an adversarial
negative test only. Chrony's Nixpkgs recipe removes its upstream nts_ke_session
unit test; this omission is not a passing test. Real interoperability is a
separate gate. Current maintainer release/security references reviewed on
2026-11-18: https://chrony-project.org/news.html and
https://www.gnutls.org/security-new.html. The pinned GnuTLS is 3.8.13, meeting
the version corrections listed there. Complete native CVE coverage is not
claimed for the fixture closure.

[`nts_guest.py`](../../nts_guest.py) uses the upstream u64-length-prefixed local JSON observation,
with a 64 KiB cap and socket timeout. It checks stratum, NTS state, endpoint and
fresh measurement timestamps, with per-invocation certificate rejection logs.
Cold service restarts remove the private observation directory. Warm-cookie and
cold-key-exchange outages are separate. No raw NTS keys/cookies are recorded.
Negative scenarios cannot pass using a previous client's observation socket.
The fixture lowers only polling intervals and supplies its explicit test CA.

The smoke application now contains curl and BusyBox instead of Python. DNS is
verified by a hostname TLS request and curl's observed peer address; TLS uses
an explicit fixture CA. BusyBox httpd serves the published-port control.
