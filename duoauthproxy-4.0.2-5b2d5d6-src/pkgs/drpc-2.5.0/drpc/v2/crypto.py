#
# Copyright (c) 2013 Duo Security
# All Rights Reserved
#
import base64
import hmac
import hashlib
import time
import string

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

ENCRYPT_PLAIN = 0
ENCRYPT_AES256CFB = 1
ENCRYPT_TYPES = set((ENCRYPT_PLAIN, ENCRYPT_AES256CFB))
SIG_WINDOW = 300
DRPC_SALT = 'biFoEkNbkyyFcIKvi3ao5An6OIdPmEgHYJemD67eThE='
SECRET_KEY_CHARS = string.ascii_letters + string.digits
SECRET_KEY_LEN = 32


def sign_message(secret, data_bytes, sig_time):
    return _hmac_sha256(secret, data_bytes, sig_time)


def _hmac_sha256(key_bytes, data_bytes, sig_time):
    """
    Return the signature string for the given time and key.
    """
    data_bytes = base64.b64encode(data_bytes)
    time_bytes = bytes(str(sig_time), 'utf8')
    canon_bytes = data_bytes + b'|' + time_bytes
    return hmac.HMAC(key_bytes, canon_bytes, hashlib.sha256).hexdigest()


def verify_sig(data_bytes, sig, drpc_creds, now=None, sig_window=SIG_WINDOW):
    """
    Return True iff the signature is correct.

    now: time (accounting for offset from Duo servers). None if you want system time
    """
    if not isinstance(sig, dict):
        return False

    if not now:
        now = int(time.time())

    sig_time = sig.get('time')
    sig_sig = sig.get('sig')
    if not (sig_time and sig_sig):
        return False

    if abs(sig_time - now) > sig_window:
        return False

    actual_sig = sign_message(drpc_creds.get_secret(), data_bytes, str(sig_time))
    return hmac.compare_digest(sig_sig, actual_sig)


def generate_ephemeral_keys():
    """
    Return a tuple (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)
    """
    private_key = ec.generate_private_key(ec.SECP384R1(),
                                          default_backend())

    def no_private_key_serialization(*args):
        raise TypeError("Ephemeral private keys cannot be serialized")

    private_key.private_bytes = no_private_key_serialization
    private_key.private_numbers = no_private_key_serialization

    return (private_key.public_key(), private_key)

def _compute_ecdh_shared_secret(remote_public_key, my_private_key):
    """
    my_private_key (ec.EllipticCurvePrivateKey) - Private key object from local DRPC client/server
    remote_public_key (ec.EllipticCurvePublicKey) - Public key object from remote DRPC client/server

    Return a shared secret using ECDH
    """
    return my_private_key.exchange(ec.ECDH(), remote_public_key)


def derive_shared_keys(remote_public_key, my_private_key):
    """
    my_private_key (ec.EllipticCurvePrivateKey) - Private key object from local DRPC client/server
    remote_public_key (ec.EllipticCurvePublicKey) - Public key object from remote DRPC client/server

    Return a pair of random SECRET_KEY_LEN-character base64 encoded keys in the form (signing skey, encyrption skey)
    """
    shared_secret = _compute_ecdh_shared_secret(
        remote_public_key, my_private_key)
    combined_key = HKDF(
        algorithm=hashes.SHA256(),
        length=SECRET_KEY_LEN * 2,
        salt=base64.standard_b64decode(DRPC_SALT),
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    signing_key, encryption_key = combined_key[:SECRET_KEY_LEN], combined_key[SECRET_KEY_LEN:SECRET_KEY_LEN * 2]

    return (base64.urlsafe_b64encode(signing_key),
            base64.urlsafe_b64encode(encryption_key))


def serialize_ephemeral_key(public_key):
    """
Serialize the public key object into a form suitable for sending to Duo via an API call

    Args:
        public_key (EllipticCurvePublicKey): a public key to serialize

    Returns:
        (bytes) the serialized public key
    """
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


def deserialize_ephemeral_key(ser_public_key):
    """
    Deserialize the unicode representation of a public key into the public key object

    Args:
        ser_public_key (unicode): a serialized public key
    Returns:
        The public key object represented by the unicode

    """
    key_bytes = ser_public_key.encode('UTF-8')
    return serialization.load_pem_public_key(key_bytes, backend=default_backend())
