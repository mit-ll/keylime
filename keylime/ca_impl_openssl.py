import datetime
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key
from cryptography.x509 import Certificate, CertificateBuilder, Name
from cryptography.x509.oid import NameOID

from keylime import config
from keylime.types import CERTIFICATE_PRIVATE_KEY_TYPES


def mk_cert_valid(cert_req: CertificateBuilder, days: int = 365) -> CertificateBuilder:
    """
    Make a cert valid from now and til 'days' from now.
    Args:
       cert_req -- cryptography.x509.base.CertificateBuilder
       days -- number of days cert is valid for from now.
    Returns: updated cryptography.x509.base.CertificateBuilder
    """

    one_day = datetime.timedelta(1, 0, 0)
    today = datetime.datetime.now(datetime.timezone.utc)
    cert_req = cert_req.not_valid_before(today)
    cert_req = cert_req.not_valid_after(today + (one_day * days))
    return cert_req


def mk_name(component: str, common_name: str) -> Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, config.get(component, "cert_country")),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.get(component, "cert_state")),
            x509.NameAttribute(NameOID.LOCALITY_NAME, config.get(component, "cert_locality")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get(component, "cert_organization")),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.get(component, "cert_org_unit")),
        ]
    )


def mk_request(component: str, bits: int, common_name: str) -> Tuple[CertificateBuilder, RSAPrivateKey]:
    """
    Create a X509 request with the given number of bits in they key.
    Args:
      bits -- number of RSA key bits
      common_name -- common name in the request
    Returns a X509 request and the private key
    """

    privkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )

    cert_req = x509.CertificateBuilder()

    subject = mk_name(component, common_name)
    cert_req = cert_req.subject_name(subject)
    return cert_req, privkey


def mk_cacert(component: str, name: Optional[str] = None) -> Tuple[Certificate, RSAPrivateKey, RSAPublicKey]:
    """
    Make a CA certificate.
    Returns the certificate, private key and public key.
    """

    if name is None:
        name = config.get(component, "cert_ca_name")
    cert_req, privkey = mk_request(component, config.getint(component, "cert_bits"), name)

    pubkey = privkey.public_key()
    cert_req = cert_req.public_key(pubkey)

    cert_req = cert_req.serial_number(1)
    cert_req = mk_cert_valid(cert_req, config.getint(component, "cert_ca_lifetime"))
    cert_req = cert_req.issuer_name(mk_name(component, name))

    # Extensions.
    extensions = [
        # Basic Constraints.
        (x509.BasicConstraints(ca=True, path_length=None), True),
        # Subject Key Identifier.
        (x509.SubjectKeyIdentifier.from_public_key(pubkey), False),
        # CRL Distribution Points.
        (
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(config.get(component, "cert_crl_dist")),
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    ),
                ]
            ),
            False,
        ),
        # Key Usage.
        (
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        ),
        # Required by RFC 5280 (section 4.2.1.1) and enforced by default in Python 3.13 and up
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(pubkey), False),
    ]

    for ext, critical in extensions:
        cert_req = cert_req.add_extension(ext, critical)

    cert = cert_req.sign(
        private_key=privkey,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    return cert, privkey, pubkey


def mk_signed_cert(
    component: str, cacert: Certificate, ca_privkey: CERTIFICATE_PRIVATE_KEY_TYPES, name: str, serialnum: int
) -> Tuple[Certificate, RSAPrivateKey]:
    """
    Create a CA cert + server cert + server private key.
    """

    cert_req, privkey = mk_request(component, config.getint(component, "cert_bits"), common_name=name)
    pubkey = privkey.public_key()
    cert_req = cert_req.public_key(pubkey)

    cert_req = cert_req.serial_number(serialnum)
    cert_req = mk_cert_valid(cert_req)
    cert_req = cert_req.issuer_name(cacert.issuer)

    # Extensions.
    extensions = [
        # OID 2.16.840.1.113730.1.13 is Netscape Comment.
        # http://oid-info.com/get/2.16.840.1.113730.1.13
        x509.UnrecognizedExtension(
            oid=x509.ObjectIdentifier("2.16.840.1.113730.1.13"),
            value=b"SSL Server",
        ),
        # Subject Alternative Name.
        x509.SubjectAlternativeName([x509.DNSName(name)]),
        # CRL Distribution Points.
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(config.get(component, "cert_crl_dist")),
                    ],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]
        ),
        # Required by RFC 5280 (section 4.2.1.1) and enforced by default in Python 3.13 and up
        x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key()),  # type: ignore
    ]

    for ext in extensions:
        cert_req = cert_req.add_extension(ext, critical=False)

    cert = cert_req.sign(
        private_key=ca_privkey,  # pyright: ignore[reportArgumentType]
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )
    return cert, privkey


def gencrl(serials: List[int], cert: str, ca_pk: str) -> bytes:
    ca_cert = x509.load_pem_x509_certificate(cert.encode())
    priv_key = load_pem_private_key(ca_pk.encode(), None, backend=default_backend())
    date_now = datetime.datetime.now(datetime.timezone.utc)

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.issuer)
    builder = builder.last_update(date_now)
    builder = builder.next_update(date_now)

    for serial in serials:
        cert_builder = x509.RevokedCertificateBuilder()
        cert_builder = cert_builder.serial_number(int(serial))
        cert_builder = cert_builder.revocation_date(date_now)
        builder = builder.add_revoked_certificate(cert_builder.build())

    if not isinstance(
        priv_key, (EllipticCurvePrivateKey, RSAPrivateKey, DSAPrivateKey, Ed448PrivateKey, Ed25519PrivateKey)
    ):
        raise ValueError(f"Unsupported key type {type(priv_key).__name__}")
    crl = builder.sign(private_key=priv_key, algorithm=hashes.SHA256(), backend=default_backend())
    return crl.public_bytes(encoding=Encoding.DER)
