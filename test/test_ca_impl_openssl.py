import os
import sys
import unittest
from pathlib import Path

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import CRLDistributionPoints

from keylime import ca_impl_openssl

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
CODE_ROOT = f"{PACKAGE_ROOT}/keylime/"

# Custom imports
sys.path.insert(0, CODE_ROOT)


class OpenSSL_Test(unittest.TestCase):
    def test_openssl(self):
        _ = ca_impl_openssl.mk_cacert("verifier", "my ca")
        (ca_cert, ca_pk, _) = ca_impl_openssl.mk_cacert("verifier")
        cert, _ = ca_impl_openssl.mk_signed_cert("verifier", ca_cert, ca_pk, "cert", 4)

        pubkey = ca_cert.public_key()
        assert isinstance(pubkey, RSAPublicKey)
        assert cert.signature_hash_algorithm is not None
        try:
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except crypto_exceptions.InvalidSignature:
            self.fail("Certificate signature validation failed.")

        # Make sure serial number in cert is 4.
        self.assertIs(type(cert.serial_number), int)
        self.assertEqual(cert.serial_number, 4)

    def test_openssl_crl_dist(self):
        os.environ["KEYLIME_VERIFIER_CERT_CRL_DIST"] = "http://foobar.org"
        _ = ca_impl_openssl.mk_cacert("verifier", "my ca")
        (ca_cert, ca_pk, _) = ca_impl_openssl.mk_cacert("verifier")
        cert, _ = ca_impl_openssl.mk_signed_cert("verifier", ca_cert, ca_pk, "cert", 4)

        pubkey = ca_cert.public_key()
        assert isinstance(pubkey, RSAPublicKey)
        assert cert.signature_hash_algorithm is not None
        try:
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except crypto_exceptions.InvalidSignature:
            self.fail("Certificate signature validation failed.")

        # Make sure serial number in cert is 4.
        self.assertIs(type(cert.serial_number), int)
        self.assertEqual(cert.serial_number, 4)
        self.assertEqual(
            cert.extensions.get_extension_for_class(CRLDistributionPoints).value[0].full_name[0].value,
            os.environ["KEYLIME_VERIFIER_CERT_CRL_DIST"],
        )


if __name__ == "__main__":
    unittest.main()
