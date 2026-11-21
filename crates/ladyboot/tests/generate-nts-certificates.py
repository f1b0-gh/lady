"""Generate PUBLIC synthetic keys/certificates, never production trust material.

Requires cryptography (initial generation: 41.0.7). Retained PEM files are exact
reproduction inputs; a regeneration intentionally creates new keys and serials.
Fixed validity windows match network_vm.py's explicit fixture RTC.
"""
from datetime import datetime
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def main():
    destination = Path(sys.argv[1])
    destination.mkdir(mode=0o700, exist_ok=False)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Ladyboot PUBLIC test CA')])
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(datetime(2020, 1, 1)).not_valid_after(datetime(2100, 1, 1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    (destination / 'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (destination / 'server-key.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    for name, hostname, start, end in [
        ('valid', 'nts.test', 2020, 2100), ('wrong-name', 'other.test', 2020, 2100),
        ('expired', 'nts.test', 2020, 2025), ('future', 'nts.test', 2090, 2100),
    ]:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(datetime(start, 1, 1)).not_valid_after(datetime(end, 1, 1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        (destination / (name + '.pem')).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # CA private key is unnecessary for reproducing tests and is not retained.


if __name__ == '__main__':
    main()
