import hashlib
import hmac
import struct
from itertools import zip_longest
from random import SystemRandom
from types import ModuleType
from typing import Any, Callable, Tuple, Union

from OpenSSL import SSL
from pyrad.packet import AuthPacket

from duoauthproxy.lib.md5_wrapper import Depends

_generator = SystemRandom()

# The ID for Microsoft attributes when setting the Vendor-Specific attribute
MICROSOFT_VENDOR_ID = 311

# The vendor types (represented by integers) of the MS-MPPE-Send-Key and
# MS-MPPE-Recv-Key per RFC 2548
MS_MPPE_SEND_KEY_TYPE = 16
MS_MPPE_RECV_KEY_TYPE = 17


def P_hash(
    secret: bytes,
    seed: bytes,
    hash_data: Union[str, Callable[[], Any], ModuleType, None],
    length: int,
) -> bytes:
    """ data expansion function as defined in RFC 2246
        Expand hash algorithm until desired length """
    output = b""
    A = []
    a = 0
    A.append(hmac.new(secret, seed, hash_data).digest())  # A(1)

    while len(output) < length:
        output += hmac.new(secret, A[a] + seed, hash_data).digest()
        A.append(hmac.new(secret, A[a], hash_data).digest())
        a += 1

    return output


def strxor(str1: bytes, str2: bytes) -> bytes:
    output = b""
    for c1, c2 in zip_longest(str1, str2):
        c1 = c1 or 0
        c2 = c2 or 0
        output += bytes([c1 ^ c2])
    return output


def get_mppe_keys(
    label: bytes,
    ssl_connection: SSL.Connection,
) -> Tuple[bytes, bytes]:
    """
    Generate MS-MPPE-Send/Recv-Key as defined in RFC 2548. AuthProxy ship with OpenSSL 1.0.2o,
    to support TLS 1.2, randomness is generated via export_keying_material.
    """
    # Openssl return bytes contain recv_key[:32] and send_key[32:64]
    randomstuff = ssl_connection.export_keying_material(label, 64)

    recv_key = randomstuff[:32]
    send_key = randomstuff[32:64]
    return recv_key, send_key


def encrypt_mppe(
    plain: bytes, secret: bytes, authenticator: bytes, salt: bytes
) -> bytes:
    """
    Encrypt an MPPE Send or Recv key using method described in RFC 2548 2.4.2 and 2.4.3

    Args:
        plain: The plaintext key to encrypt
        secret: The secret to encrypt the key with
        authenticator: The authenticator to encrypt the key with. Should be 16 bytes.
        salt: The salt to encrypt the key with. Should be 2 bytes.
    """
    plainlen = len(plain)
    plain = bytes([plainlen]) + plain  # Add Key-Len

    C = b""
    b = hashlib.md5(secret + authenticator + salt, used_for_security=Depends).digest()  # type: ignore

    # Per the RFC, operate on the plaintext key in 16 byte chunks, concatenating
    # the result of each chunk together to get the final encrypted key
    for p in (plain[x : x + 16] for x in range(0, len(plain), 16)):
        c = strxor(p, b)
        C += c
        b = hashlib.md5(secret + c, used_for_security=Depends).digest()  # type: ignore

    return C


def decrypt_mppe(
    encrypted_key: bytes, secret: bytes, authenticator: bytes, salt: bytes
) -> bytes:
    """
    Decrypt an MPPE Send or Recv key using method described in RFC 2548 2.4.2 and 2.4.3.

    Args:
        encrypted_key: The encrypted key to decrypt
        secret: The secret used to encrypt the key
        authenticator: The authenticator used to encrypt the key. Should be 16 bytes.
        salt: The salt used to encrypt the key. Should be 2 bytes.

    Returns:
        The decrypted key with format (key_length + key + padding), where
        key_length is 1 byte and padding is the necessary length to make the total
        key length a factor of 16.
    """
    plaintext_key = b""
    b = hashlib.md5(secret + authenticator + salt, used_for_security=Depends).digest()  # type: ignore

    # Per the RFC, operate on the encrypted key in 16 byte chunks, concatenating
    # the result of each chunk together to get the final plaintext key
    for c in (encrypted_key[x : x + 16] for x in range(0, len(encrypted_key), 16)):
        p = strxor(c, b)
        plaintext_key += p
        b = hashlib.md5(secret + c, used_for_security=Depends).digest()  # type: ignore

    return plaintext_key


def decrypt_and_extract_mppe_key(
    encrypted_key: bytes, secret: bytes, authenticator: bytes, salt: bytes
) -> bytes:
    """Decrypts an MPPE Send or Recv key and removes the key length and any padding from it, returning just the key"""
    decrypted_key = decrypt_mppe(encrypted_key, secret, authenticator, salt)

    # The decrypted key has format (key_length + key + padding).
    # Remove the length and any padding so we just have the actual key left
    key_length = decrypted_key[0]
    decrypted_key_without_length_or_padding = decrypted_key[1 : key_length + 1]
    return decrypted_key_without_length_or_padding


def add_mppe(
    reply: AuthPacket,
    send_key: bytes,
    recv_key: bytes,
    secret: bytes,
    authenticator: bytes,
) -> None:
    """
    Add MPPE (Microsoft Point to Point Encryption) Send and Recv keys to the provided packet

    Args:
        reply: the reply to add the send key and recv key to
        send_key: The plaintext MS-MPPE-Send-Key to encrypt and add to the reply
        recv_key: The plaintext MS-MPPE-Recv-Key to encrypt and add to the reply
        secret: the RADIUS secret
        authenticator: RADIUS authenticator. Should be 16 bytes.

    """
    sodiumchloride = _generator.randint(32768, 65535)  # Leftmost bit must be set
    potassiumnitrate = _generator.randint(32768, 65535)  # Leftmost bit must be set
    send_key_salt = struct.pack(">H", sodiumchloride)
    recv_key_salt = struct.pack(">H", potassiumnitrate)

    encrypted_send_key = encrypt_mppe(send_key, secret, authenticator, send_key_salt)
    encrypted_recv_key = encrypt_mppe(recv_key, secret, authenticator, recv_key_salt)

    reply.AddAttribute(
        (MICROSOFT_VENDOR_ID, MS_MPPE_SEND_KEY_TYPE), send_key_salt + encrypted_send_key
    )
    reply.AddAttribute(
        (MICROSOFT_VENDOR_ID, MS_MPPE_RECV_KEY_TYPE), recv_key_salt + encrypted_recv_key
    )
