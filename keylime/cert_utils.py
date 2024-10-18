import io
import os.path
import subprocess
import sys
from typing import Dict, Optional, Tuple

from cryptography import exceptions as crypto_exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate
from cryptography.x509.oid import ExtensionOID
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import pem, rfc2459, rfc4108

from keylime import keylime_logging, tpm_ek_ca
from keylime.tpm import tpm2_objects

# Issue #944 -- python-cryptography won't parse malformed certs,
# such as some Nuvoton ones we have encountered in the field.
# Unfortunately, we still have to deal with such certs anyway.

# Here we provide some helpers that use pyasn1 to parse the certificates
# when parsing them with python-cryptography fails, and in this case, we
# try to read the parsed certificate again into python-cryptograhy.

# These OIDs are taken from the SubjectAltName from section 8.1 of the TPM 2.0 Keys for Device Identity and Attestation
# https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf
OID_HW_MODULE_NAME = "1.3.6.1.5.5.7.8.4"
OID_HWTYPE_TPM = "2.23.133.1.2"

logger = keylime_logging.init_logging("cert_utils")


def is_x509_cert(cert_data: bytes) -> bool:
    """
    Determine wheter the data passed is a valid x509 cert.

    :param cert_data: bytes to check
    :return: bool, indicating whether the provided input is a valid cert
    """
    try:
        x509_pem_cert(cert_data.decode("UTF-8"))
        return True
    except Exception:
        try:
            x509_der_cert(cert_data)
            return True
        except Exception:
            return False
        return False


def x509_der_cert(der_cert_data: bytes) -> Certificate:
    """Load an x509 certificate provided in DER format
    :param der_cert_data: the DER bytes of the certificate
    :type der_cert_data: bytes
    :returns: cryptography.x509.Certificate
    """
    try:
        return x509.load_der_x509_certificate(data=der_cert_data, backend=default_backend())
    except Exception as err:
        logger.warning("Failed to parse DER data with python-cryptography: %s", err)
        pyasn1_cert = decoder.decode(der_cert_data, asn1Spec=rfc2459.Certificate())[0]
        return x509.load_der_x509_certificate(data=encoder.encode(pyasn1_cert), backend=default_backend())


def x509_pem_cert(pem_cert_data: str) -> Certificate:
    """Load an x509 certificate provided in PEM format
    :param pem_cert_data: the base-64 encoded PEM certificate
    :type pem_cert_data: str
    :returns: cryptography.x509.Certificate
    """
    try:
        return x509.load_pem_x509_certificate(data=pem_cert_data.encode("utf-8"), backend=default_backend())
    except Exception as err:
        logger.warning(
            "Failed to parse PEM data with python-cryptography (might not be strictly conforming to DER ASN.1 encoding): %s",
            err,
        )
        # Let's read the DER bytes from the base-64 PEM.
        der_data = pem.readPemFromFile(io.StringIO(pem_cert_data))
        # Now we can load it as we do in x509_der_cert().
        pyasn1_cert = decoder.decode(der_data, asn1Spec=rfc2459.Certificate())[0]
        return x509.load_der_x509_certificate(data=encoder.encode(pyasn1_cert), backend=default_backend())


def cert_signature_check(cert: Certificate, signcert: Certificate) -> bool:
    if cert.issuer != signcert.subject:
        return False

    signcert_pubkey = signcert.public_key()
    try:
        if isinstance(signcert_pubkey, RSAPublicKey):
            assert cert.signature_hash_algorithm is not None
            signcert_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(signcert_pubkey, EllipticCurvePublicKey):
            assert cert.signature_hash_algorithm is not None
            signcert_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            logger.warning("Unsupported public key type: %s", type(signcert_pubkey))
            return False
    except crypto_exceptions.InvalidSignature:
        return False

    return True


def verify_cert(cert: Certificate, tpm_cert_store: str, cert_type: str = "") -> bool:
    """Verify that the provided certificate is signed by a trusted root
    :param cert: The certificate as a cryptography.x509.Certificate
    :param tpm_cert_store: The path for the TPM certificate store
    :param cert_type: Type of certificate as string for logging
    :returns: True if the certificate can be verified, False otherwise
    """
    try:
        trusted_certs = tpm_ek_ca.cert_loader(tpm_cert_store)
    except Exception as err:
        logger.warning("Error loading trusted certificates from the TPM cert store: %s", err)
        return False

    try:
        for cert_file, pem_cert in trusted_certs.items():
            try:
                signcert = x509_pem_cert(pem_cert)
            except Exception as err:
                logger.warning("Ignoring certificate file %s due to error: %s", cert_file, str(err))
                continue

            if cert_signature_check(cert, signcert):
                logger.debug("Cert to verify matched cert: %s", cert_file)
                return True

    except Exception as err:
        # Log the exception so we don't lose the raw message
        logger.exception(err)
        raise Exception(f"Error processing {cert_type} certificate.").with_traceback(sys.exc_info()[2])

    logger.error("No Root CA matched %s Certificate", cert_type)
    return False


def check_tpm_origin(cert: Certificate, cert_type: str = "") -> bool:
    """Verify that the provided certificate is from a TPM according to the SAN
    :param cert: The certificate as a cryptography.x509.Certificate
    :param cert_type: Type of certificate as string for logging
    :returns: True if the certificate came from a TPM, or we are not sure. False if it did not come from a TPM
    """
    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if not isinstance(san_ext.value, x509.SubjectAlternativeName):
        logger.warning("%s Certificate did not contain a SubjectAltName. This may not have come from a TPM.", cert_type)
        return True
    othername = san_ext.value.get_values_for_type(x509.OtherName)[0]
    if othername.type_id.dotted_string != OID_HW_MODULE_NAME:
        logger.warning(
            "%s Certificate did not contain the HW module name. This may not have come from a TPM.", cert_type
        )
        return True
    decoded_on, _ = decoder.decode(othername.value, asn1Spec=rfc4108.HardwareModuleName())
    if str(decoded_on["hwType"]) != OID_HWTYPE_TPM:
        logger.error(
            "%s Certificate did not contain the correct hwType OID in SubjectAltName. This did not come from a TPM.",
            cert_type,
        )
        return False
    logger.debug("%s seems to have come from a TPM", cert_type)
    return True


def verify_ek(ekcert: bytes, tpm_cert_store: str) -> bool:
    """Verify that the provided EK certificate is signed by a trusted root
    :param ekcert: The Endorsement Key certificate in DER format
    :param tpm_cert_store: The path for the TPM certificate store
    :returns: True if the certificate can be verified, False otherwise
    """
    try:
        ek509 = x509_der_cert(ekcert)
    except Exception as err:
        # Log the exception so we don't lose the raw message
        logger.exception(err)
        raise Exception("Error processing ek/ekcert. Does this TPM have a valid EK?").with_traceback(sys.exc_info()[2])
    return verify_cert(ek509, tpm_cert_store, "EK")


def verify_ek_script(script: Optional[str], env: Optional[Dict[str, str]], cwd: Optional[str]) -> bool:
    if script is None:
        logger.warning("External check script (%s) not specified", script)
        return False

    script_path = os.path.abspath(script)
    if not os.path.isfile(script_path):
        if cwd is None or not os.path.isfile(os.path.abspath(os.path.join(cwd, script))):
            logger.warning("External check script (%s) not found; please make sure its path is correct", script)
            return False
        script_path = os.path.abspath(os.path.join(cwd, script))

    try:
        proc = subprocess.run(
            [script_path],
            env=env,
            shell=False,
            cwd=cwd,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            errmsg = ""
            if proc.stdout is not None:
                errmsg = proc.stdout.decode("utf-8")
            logger.error("External check script failed to validate EK: %s", errmsg)
            return False
        logger.debug("External check script successfully to validated EK")
        if proc.stdout is not None:
            logger.info("ek_check output: %s", proc.stdout.decode("utf-8"))
    except subprocess.CalledProcessError as err:
        logger.error("Error while trying to run external check script to validate EK: %s", err)
        return False
    return True


def iak_idevid_cert_checks(
    idevid_cert: bytes, iak_cert: bytes, tpm_cert_store: str
) -> Tuple[str, Optional[tpm2_objects.pubkey_type], Optional[tpm2_objects.pubkey_type]]:
    idevid_cert_509 = x509_der_cert(idevid_cert)
    iak_cert_509 = x509_der_cert(iak_cert)
    # NEEDS CRYPTO >= 38.0.0
    idevid_pub = idevid_cert_509.public_key()
    iak_pub = iak_cert_509.public_key()

    if not isinstance(idevid_pub, (RSAPublicKey, EllipticCurvePublicKey)):
        return "Error: IDevID certificate does not contain an RSA or EC public key", None, None
    if not isinstance(iak_pub, (RSAPublicKey, EllipticCurvePublicKey)):
        return "Error: IAK certificate does not contain an RSA or EC public key", None, None

    if not verify_cert(idevid_cert_509, tpm_cert_store, "IDevID"):
        return "Error: IDevID certificate could not be verified", None, None
    logger.debug("IDevID cert verified.")
    if not verify_cert(iak_cert_509, tpm_cert_store, "IAK"):
        return "Error: IAK certificate could not be verified", None, None
    logger.debug("IAK cert verified.")

    # TPM cert checks
    # Check if the IDevID and IAK certificates came from a TPM by checking the SAN
    # These checks will warn if the certificates do not contain the expected fields
    # but will only fail if the certificates have the fields but the hardware ID is incorrect
    if not check_tpm_origin(idevid_cert_509, "IDevID"):
        return "Error: IDevID certificate might not be from a TPM", None, None
    if not check_tpm_origin(iak_cert_509, "IAK"):
        return "Error: IAK certificate might not be from a TPM", None, None
    return "", idevid_pub, iak_pub
