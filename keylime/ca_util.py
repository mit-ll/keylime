"""Tools for creating a CA cert and signed server certs.

Divined from http://svn.osafoundation.org/m2crypto/trunk/tests/test_x509.py
The mk_temporary_xxx calls return a NamedTemporaryFile with certs.
Usage:
  # Create a temporary CA cert and it's private key
  cacert, cakey = mk_temporary_cacert()
  # Create a temporary server cert+key, signed by the CA
  server_cert = mk_temporary_cert(cacert.name, cakey.name, '*.server.co.uk')

Protips:
  # openssl verify -CAfile cacert.crt cacert.crt cert.crt
  # openssl x509 -in cert.crt -noout -text
  # openssl x509 -in cacert.crt -noout -text

"""

import argparse
import base64
import getpass
import glob
import io
import os
import sys
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import yaml

try:
    from yaml import CSafeDumper as SafeDumper
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader, SafeDumper  # type: ignore

from cryptography import exceptions as crypto_exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate

from keylime import ca_impl_openssl as ca_impl
from keylime import config, crypto, fs_util, keylime_logging

logger = keylime_logging.init_logging("ca-util")

global_password: Optional[str] = None


def load_cert_by_path(cert_path: str) -> Certificate:
    cert = None
    with open(cert_path, "rb") as ca_file:
        cert = x509.load_pem_x509_certificate(
            data=ca_file.read(),
            backend=default_backend(),
        )
    return cert


def read_password(component: str, key_store_pw: Optional[str] = None) -> None:
    global global_password
    if not key_store_pw:
        key_store_pw = config.get(component, "password", fallback="default")

    if key_store_pw == "default":
        logger.warning("Using 'default' password option from %s configuration file", component)
    global_password = key_store_pw


def ask_password(component: str, key_store_pw: Optional[str] = None) -> None:
    global global_password
    if not key_store_pw:
        key_store_pw = config.get(component, "password", fallback="default")

    if key_store_pw == "default":
        logger.warning(
            "The 'default' password option from CA configuration file cannot be used with keylime CLI (keylime_tenant or keylime_ca)"
        )
        key_store_pw = getpass.getpass("Please enter the password to decrypt your keystore: ")

    if not key_store_pw:
        raise Exception("You must specify a password!")
    global_password = key_store_pw


def cmd_mkcert(component: str, workingdir: str, name: str, password: Optional[str] = None) -> None:
    cwd = os.getcwd()
    mask = os.umask(0o037)
    try:
        fs_util.ch_dir(workingdir)
        priv = read_private(False)
        cacert = load_cert_by_path("cacert.crt")
        ca_pk = serialization.load_pem_private_key(priv[0]["ca"], password=None, backend=default_backend())
        if not isinstance(
            ca_pk, (EllipticCurvePrivateKey, RSAPrivateKey, DSAPrivateKey, Ed448PrivateKey, Ed25519PrivateKey)
        ):
            raise Exception(
                f"Private key of type {type(ca_pk).__name__} cannot be used for creating an x509 certificate"
            )

        cert, pk = ca_impl.mk_signed_cert(component, cacert, ca_pk, name, priv[0]["lastserial"] + 1)

        with os.fdopen(os.open(f"{name}-cert.crt", os.O_WRONLY | os.O_CREAT, 0o640), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        priv[0][name] = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption(),
        )

        # increment serial number after successful creation
        priv[0]["lastserial"] += 1

        write_private(priv)

        with os.fdopen(os.open(f"{name}-private.pem", os.O_WRONLY | os.O_CREAT, 0o640), "wb") as f:
            f.write(priv[0][name])

        with os.fdopen(os.open(f"{name}-public.pem", os.O_WRONLY | os.O_CREAT, 0o640), "wb") as f:
            f.write(
                pk.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        cc = load_cert_by_path(f"{name}-cert.crt")
        pubkey = cacert.public_key()
        assert isinstance(pubkey, rsa.RSAPublicKey)
        assert cc.signature_hash_algorithm is not None
        pubkey.verify(
            cc.signature,
            cc.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cc.signature_hash_algorithm,
        )

        logger.info("Created certificate for name %s successfully in %s", name, workingdir)
    except crypto_exceptions.InvalidSignature:
        logger.error("ERROR: Cert does not validate against CA")
    finally:
        os.umask(mask)
        os.chdir(cwd)


def cmd_import_priv(workingdir: str, priv_pem_file: str, lastserial: int) -> None:
    cwd = os.getcwd()
    try:
        with open(priv_pem_file, "rb") as priv_pem:
            pem = priv_pem.read()
        fs_util.ch_dir(workingdir)
        priv = read_private(False)
        private_key = load_pem_private_key(pem, None, default_backend())
        priv[0]["ca"] = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        priv[0]["lastserial"] = int(lastserial) + 1
        write_private(priv)
    finally:
        os.chdir(cwd)


def cmd_init(component: str, workingdir: str) -> None:
    cwd = os.getcwd()
    mask = os.umask(0o037)
    try:
        fs_util.ch_dir(workingdir)

        rmfiles("*.pem")
        rmfiles("*.crt")
        rmfiles("*.zip")
        rmfiles("*.der")
        rmfiles("private.yml")

        cacert, ca_pk, _ = ca_impl.mk_cacert(component)  # pylint: disable=W0632
        priv = read_private(False)

        # write out keys
        with open("cacert.crt", "wb") as f:
            f.write(cacert.public_bytes(serialization.Encoding.PEM))

        priv[0]["ca"] = ca_pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # store the last serial number created.
        # the CA is always serial # 1
        priv[0]["lastserial"] = 1

        write_private(priv)

        with os.fdopen(os.open("ca-public.pem", os.O_WRONLY | os.O_CREAT, 0o640), "wb") as f:
            f.write(
                ca_pk.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        # generate an empty crl
        cacert_str = cacert.public_bytes(serialization.Encoding.PEM).decode()
        crl = ca_impl.gencrl([], cacert_str, priv[0]["ca"].decode())

        if isinstance(crl, str):
            crl = crl.encode("utf-8")

        with open("cacrl.der", "wb") as f:
            f.write(crl)
        convert_crl_to_pem("cacrl.der", "cacrl.pem")

        # Sanity checks...
        cac = load_cert_by_path("cacert.crt")
        pubkey = cacert.public_key()
        assert isinstance(pubkey, rsa.RSAPublicKey)
        assert cac.signature_hash_algorithm is not None
        pubkey.verify(
            cac.signature,
            cac.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cac.signature_hash_algorithm,
        )

        logger.info("CA certificate created successfully in %s", workingdir)
    except crypto_exceptions.InvalidSignature:
        logger.error("ERROR: Cert does not self validate")
    finally:
        os.chdir(cwd)
        os.umask(mask)


def cmd_certpkg(workingdir: str, name: str, insecure: bool = False) -> Tuple[bytes, int, str]:
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        # zip up the crt, private key, and public key

        with open("cacert.crt", "rb") as f:
            cacert = f.read()

        with open(f"{name}-public.pem", "rb") as f:
            pub = f.read()

        with open(f"{name}-cert.crt", "rb") as f:
            cert = f.read()

        with open("cacrl.der", "rb") as f:
            crl = f.read()

        with open("cacrl.pem", "rb") as f:
            crlpem = f.read()

        cert_obj = x509.load_pem_x509_certificate(
            data=cert,
            backend=default_backend(),
        )

        serial = cert_obj.serial_number
        subject = cert_obj.subject.rfc4514_string()

        priv = read_private(False)
        private = priv[0][name]

        with open(f"{name}-private.pem", "rb") as f:
            prot_priv = f.read()

        # no compression to avoid extraction errors in tmpfs
        sf = io.BytesIO()
        with zipfile.ZipFile(sf, "w", compression=zipfile.ZIP_STORED) as f:
            f.writestr(f"{name}-public.pem", pub)
            f.writestr(f"{name}-cert.crt", cert)
            f.writestr(f"{name}-private.pem", private)
            f.writestr("cacert.crt", cacert)
            f.writestr("cacrl.der", crl)
            f.writestr("cacrl.pem", crlpem)
        pkg = sf.getvalue()

        if insecure:
            logger.warning("Unprotected private keys in cert package being written to disk")
            with open(f"{name}-pkg.zip", "wb") as f:
                f.write(pkg)
        else:
            # actually output the package to disk with a protected private key
            with zipfile.ZipFile(f"{name}-pkg.zip", "w", compression=zipfile.ZIP_STORED) as f:
                f.writestr(f"{name}-public.pem", pub)
                f.writestr(f"{name}-cert.crt", cert)
                f.writestr(f"{name}-private.pem", prot_priv)
                f.writestr("cacert.crt", cacert)
                f.writestr("cacrl.der", crl)
                f.writestr("cacrl.pem", crlpem)

        logger.info("Creating cert package for %s in %s-pkg.zip", name, name)

        return pkg, serial, subject
    finally:
        os.chdir(cwd)


def convert_crl_to_pem(derfile: str, pemfile: str) -> None:
    with open(derfile, "rb") as der_f, open(pemfile, "wb") as pem_f:
        der_crl = der_f.read()
        pem_f.write(x509.load_der_x509_crl(der_crl).public_bytes(encoding=serialization.Encoding.PEM))


def cmd_revoke(workingdir: str, name: Optional[str] = None, serial: Optional[int] = None) -> bytes:
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        priv = read_private(False)

        if name is not None and serial is not None:
            raise Exception("You may not specify a cert and a serial at the same time")
        if name is None and serial is None:
            raise Exception("You must specify a cert or a serial to revoke")
        if name is not None:
            # load up the cert
            cert = load_cert_by_path(f"{name}-cert.crt")
            serial = cert.serial_number

        # convert serial to string
        serial_str = str(serial)

        # get the ca key cert and keys as strings
        with open("cacert.crt", encoding="utf-8") as f:
            cacert = f.read()
        ca_pk = priv[0]["ca"].decode("utf-8")

        if serial_str not in priv[0]["revoked_keys"]:
            priv[0]["revoked_keys"].append(serial_str)

        crl = ca_impl.gencrl(priv[0]["revoked_keys"], cacert, ca_pk)

        write_private(priv)

        # write out the CRL to the disk
        if os.stat("cacrl.der").st_size:
            with open("cacrl.der", "wb") as f:
                f.write(crl)
            convert_crl_to_pem("cacrl.der", "cacrl.pem")

    finally:
        os.chdir(cwd)
    return crl


def rmfiles(path: str) -> None:
    files = glob.glob(path)
    for f in files:
        os.remove(f)


def write_private(inp: Tuple[Dict[str, Any], str]) -> None:
    priv = inp[0]
    salt = inp[1]

    priv_encoded = yaml.dump(priv, Dumper=SafeDumper)
    assert isinstance(global_password, str)
    key = crypto.kdf(global_password, salt)
    ciphertext = crypto.encrypt(priv_encoded.encode("utf-8"), key)
    towrite = {"salt": salt, "priv": ciphertext}

    mask = os.umask(0o037)
    with os.fdopen(os.open("private.yml", os.O_WRONLY | os.O_CREAT, 0o640), "w", encoding="utf-8") as f:
        yaml.dump(towrite, f, Dumper=SafeDumper)
    os.umask(mask)


def read_private(warn: bool = False) -> Tuple[Dict[str, Any], str]:
    if os.path.exists("private.yml"):
        with open("private.yml", encoding="utf-8") as f:
            toread = yaml.load(f, Loader=SafeLoader)
        assert isinstance(global_password, str)
        key = crypto.kdf(global_password, toread["salt"])
        try:
            plain = crypto.decrypt(toread["priv"], key)
        except crypto_exceptions.InvalidTag as e:
            raise Exception("Invalid password for keystore") from e

        return yaml.load(plain, Loader=SafeLoader), toread["salt"]

    if warn:
        # file doesn't exist, just invent a salt
        logger.warning("Private certificate data %s does not exist yet.", os.path.abspath("private.yml"))
        logger.warning("Keylime will attempt to load private certificate data again when it is needed.")
    return {"revoked_keys": [], "ca": b""}, base64.b64encode(crypto.generate_random_key()).decode()


def main(argv: List[str] = sys.argv) -> None:  # pylint: disable=dangerous-default-value
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument(
        "-c",
        "--command",
        action="store",
        dest="command",
        required=True,
        help="valid commands are init,create,pkg,revoke,listen,import-priv",
    )
    parser.add_argument("-n", "--name", action="store", help="the common name of the certificate to create")
    parser.add_argument("-d", "--dir", action="store", help="use a custom directory to store certificates and keys")
    parser.add_argument(
        "-i",
        "--insecure",
        action="store_true",
        default=False,
        help="create cert packages with unprotected private keys and write them to disk.  USE WITH CAUTION!",
    )
    parser.add_argument(
        "-f", "--file", action="store", default="ca-private.pem", help="file path of the private key of the CA cert"
    )
    parser.add_argument("-s", "--serial", action="store", help="last serial number the CA has used")
    parser.add_argument(
        "--component",
        action="store",
        help="name of the component used to retrieve settings " "from its corresponding configuration file.",
    )
    args = parser.parse_args(argv[1:])

    if args.dir is None:
        if not os.access(config.WORK_DIR, os.R_OK + os.W_OK):
            logger.error(
                "If you don't specify a working directory, this process must be run as a user with access to %s",
                config.WORK_DIR,
            )
            sys.exit(-1)
        workingdir = config.CA_WORK_DIR
    else:
        workingdir = args.dir

    # set a conservative general umask
    os.umask(0o077)

    if args.command == "init":
        if args.component is None:
            logger.error("you must pass in the name of the component using --component")
            parser.print_help()
            sys.exit(-1)
        ask_password(args.component, None)
        cmd_init(args.component, workingdir)
    elif args.command == "create":
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        if args.component is None:
            logger.error("you must pass in the name of the component using --component")
            parser.print_help()
            sys.exit(-1)
        ask_password(args.component, None)
        cmd_mkcert(args.component, workingdir, args.name)
    elif args.command == "pkg":
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        if args.component is None:
            logger.error("you must pass in the name of the component using --component")
            parser.print_help()
            sys.exit(-1)
        ask_password(args.component, None)
        cmd_certpkg(workingdir, args.name, args.insecure)
    elif args.command == "revoke":
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        if args.component is None:
            logger.error("you must pass in the name of the component using --component")
            parser.print_help()
            sys.exit(-1)
        ask_password(args.component, None)
        cmd_revoke(workingdir, args.name)
    elif args.command == "import-priv":
        if args.serial is None:
            logger.error("you must pass in the last serial number the CA has used using -s (or --serial)")
            parser.print_help()
            sys.exit(-1)
        if args.component is None:
            logger.error("you must pass in the name of the component using --component")
            parser.print_help()
            sys.exit(-1)
        ask_password(args.component, None)
        cmd_import_priv(workingdir, args.file, args.serial)
    else:
        logger.error("Invalid command: %s", args.command)
        parser.print_help()
        sys.exit(-1)
