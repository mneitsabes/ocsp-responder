import argparse
import base64
import datetime
import logging
import threading
import time
from pathlib import Path
import os

import uvicorn
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import ocsp
from fastapi import FastAPI, Request, Response, HTTPException

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def load_cert(p: Path) -> x509.Certificate:
    """
    Load x509 certificate from file

    :param p: the certificate file path
    :return: the certificate
    :raise RuntimeError: in case of an error
    """
    try:
        with open(p, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    except FileNotFoundError:
        raise RuntimeError(f'Certificate {p} not found')
    except OSError:
        raise RuntimeError(f'Cannot read certificate {p}')
    except ValueError:
        raise RuntimeError(f'Invalid certificate {p}')


def load_key(p: Path) -> PrivateKeyTypes:
    """
    Load x509 private key from file

    :param p: the private key file path
    :return: the private key
    :raise RuntimeError: in case of an error
    """
    try:
        with open(p, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    except FileNotFoundError:
        raise RuntimeError(f'Private key {p} not found')
    except OSError:
        raise RuntimeError(f'Cannot read private key {p}')
    except ValueError:
        raise RuntimeError(f'Invalid private key {p}')

def load_crl(p: Path) -> x509.CertificateRevocationList:
    try:
        with open(p, "rb") as f:
            data = f.read()
            if b"BEGIN X509 CRL" in data:
                return x509.load_pem_x509_crl(data, default_backend())

            return x509.load_der_x509_crl(data, default_backend())
    except FileNotFoundError:
        raise RuntimeError(f'CRL {p} not found')
    except OSError:
        raise RuntimeError(f'Cannot read CRL {p}')
    except ValueError:
        raise RuntimeError(f'Invalid CRL {p}')


class CRLCache:
    """
    CRL caching logic
    """
    def __init__(self, crl_path: Path, ttl):
        self.crl_path = crl_path
        self.ttl = ttl

        self.lock = threading.Lock()

        self._crl = None
        self._loaded_at = 0

    def load(self) -> None:
        """
        Load the CRL from the disk
        """
        with self.lock:
            self._crl = load_crl(self.crl_path)
            self._loaded_at = time.time()

            logging.info('CRL reloaded')

    def get(self) -> x509.CertificateRevocationList:
        """
        Get the CRL.

        If the CRL is not loaded or too old, reload it from the disk
        :return: the CRL
        """
        if not self._crl or time.time() - self._loaded_at > self.ttl:
            self.load()

        return self._crl


app = FastAPI(title="OCSP Responder")

CRL_CACHE = None
OCSP_CERT = None
OCSP_KEY = None
OCSP_ISSUER_CA = None
ISSUER_NAME_HASH = None
ISSUER_KEY_HASH = None
NEXT_UPDATE_HOURS = None

def build_ocsp_response(ocsp_req: ocsp.OCSPRequest) -> ocsp.OCSPResponse:
    """
    Build the OCSP response for the provided OCSP request
    
    :param ocsp_req: the OCSP request
    :return: the OCSP response
    """
    log = f'Request received for serial {ocsp_req.serial_number}, result is '

    if ocsp_req.issuer_name_hash != ISSUER_NAME_HASH:
        log += 'ERROR : wrong issuer name hash'
        logging.warning(log)

        raise HTTPException(400, "Wrong issuer name hash")

    if ocsp_req.issuer_key_hash != ISSUER_KEY_HASH:
        log += 'ERROR : wrong issuer key hash'
        logging.warning(log)

        raise HTTPException(400, "Wrong issuer key hash")

    builder = ocsp.OCSPResponseBuilder()

    # Used nonce if provided by the client
    try:
        nonce = ocsp_req.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    except x509.ExtensionNotFound:
        pass

    serial = ocsp_req.serial_number
    status = ocsp.OCSPCertStatus.GOOD

    revocation_time = None
    revocation_reason = None

    crl = CRL_CACHE.get()

    for revoked in crl:
        if revoked.serial_number == serial:
            status = ocsp.OCSPCertStatus.REVOKED
            revocation_time = revoked.revocation_date_utc
            revocation_reason = x509.ReasonFlags.key_compromise
            break

    log += 'GOOD' if status == ocsp.OCSPCertStatus.GOOD else 'REVOKED'
    logging.info(log)

    builder = builder.certificates([OCSP_CERT])

    builder = builder.add_response_by_hash(
        issuer_name_hash=ocsp_req.issuer_name_hash,
        issuer_key_hash=ocsp_req.issuer_key_hash,
        serial_number=ocsp_req.serial_number,
        algorithm=ocsp_req.hash_algorithm,
        cert_status=status,
        this_update=datetime.datetime.now(datetime.UTC),
        next_update=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=NEXT_UPDATE_HOURS),
        revocation_time=revocation_time,
        revocation_reason=revocation_reason
    )

    builder = builder.responder_id(
        ocsp.OCSPResponderEncoding.HASH,
        OCSP_CERT
    )

    return builder.sign(
        private_key=OCSP_KEY,
        algorithm=hashes.SHA256(),

    )

@app.post("/")
async def ocsp_post(request: Request):
    """
    Handle OCSP HTTP POST requests.

    :param request: the request
    :return: the response
    """
    try:
        der = await request.body()
        ocsp_req = ocsp.load_der_ocsp_request(der)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid OCSP request")

    ocsp_resp = build_ocsp_response(ocsp_req)

    return Response(
        content=ocsp_resp.public_bytes(serialization.Encoding.DER),
        media_type="application/ocsp-response"
    )

@app.get("/{b64_request:path}")
def ocsp_get(b64_request: str):
    """
    Handle OCSP HTTP GET requests.

    :param b64_request: the request in base64 format
    :return: the response
    """
    try:
        padding = "=" * (-len(b64_request) % 4)
        der = base64.urlsafe_b64decode(b64_request + padding)
        ocsp_req = ocsp.load_der_ocsp_request(der)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid OCSP GET request")

    ocsp_resp = build_ocsp_response(ocsp_req)

    with open('resp.der', 'wb') as f_out:
        f_out.write(ocsp_resp.public_bytes(serialization.Encoding.DER))

    return Response(
        content=ocsp_resp.public_bytes(serialization.Encoding.DER),
        media_type="application/ocsp-response"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, prog='ocsp_responder')
    parser.add_argument("--host",  default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=80, help="Bind port (default: 80)")
    parser.add_argument("--crl", required=True, type=Path, help="CRL file (PEM or DER)")
    parser.add_argument("--ocsp-cert", required=True, type=Path, help="OCSP responder certificate (PEM)")
    parser.add_argument("--ocsp-key", required=True, type=Path, help="OCSP responder private key (PEM)")
    parser.add_argument("--ca", required=True, type=Path, help="OCSP issuer CA (intermediate CA, PEM)")
    parser.add_argument("--cache-ttl", type=int, default=300, help="CRL cache TTL in seconds (default: 300)")
    parser.add_argument("--next-update", type=int, default=6, help="Next update in hours (default: 6)")
    parser.add_argument("--log-file", type=Path, help="Log to file")

    args = parser.parse_args()

    logging.getLogger().setLevel(logging.ERROR)

    try:
        OCSP_CERT = load_cert(args.ocsp_cert)
        OCSP_KEY = load_key(args.ocsp_key)

        OCSP_ISSUER_CA = load_cert(args.ca)
        ISSUER_NAME_HASH = hashes.Hash(hashes.SHA1())
        ISSUER_NAME_HASH.update(
            OCSP_ISSUER_CA.subject.public_bytes(default_backend())
        )
        ISSUER_NAME_HASH = ISSUER_NAME_HASH.finalize()

        ISSUER_KEY_HASH = OCSP_ISSUER_CA.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest

        CRL_CACHE = CRLCache(args.crl, args.cache_ttl)
        CRL_CACHE.load() # start up test

        NEXT_UPDATE_HOURS = args.next_update

        if args.log_file:
            if os.path.isdir(args.log_file):
                logging.error('Log file is a directory')

            file_handler = logging.FileHandler(args.log_file)
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                                    datefmt='%Y-%m-%d %H:%M:%S'))
            logging.getLogger().addHandler(file_handler)

    except RuntimeError as e:
        logging.error(e)
        exit(-1)

    uvicorn.run(app, host=args.host, port=args.port)
