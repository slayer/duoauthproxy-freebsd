import hashlib
import hmac
import struct
from random import SystemRandom
from itertools import zip_longest
from typing import Callable, Union, Any, List
from types import ModuleType

from OpenSSL import SSL
from pyrad.packet import AuthPacket
from duoauthproxy.lib.md5_wrapper import Depends

OPENSSL_VERSION_101 = int('0x10001000', 16)
_generator = SystemRandom()


def P_hash(secret: bytes, seed: bytes, hash_data: Union[str, Callable[[], Any], ModuleType, None], length: int) -> bytes:
    ''' data expansion function as defined in RFC 2246
        Expand hash algorithm until desired length '''
    output = b''
    A = []
    a = 0
    A.append(hmac.new(secret, seed, hash_data).digest())  # A(1)

    while len(output) < length:
        output += hmac.new(secret, A[a] + seed, hash_data).digest()
        A.append(hmac.new(secret, A[a], hash_data).digest())
        a += 1

    return output


def strxor(str1: bytes, str2: bytes) -> bytes:
    output = b''
    for c1, c2 in zip_longest(str1, str2):
        c1 = c1 or 0
        c2 = c2 or 0
        output += bytes([c1 ^ c2])
    return output


def PRF(secret: bytes, seed: bytes, length: int) -> bytes:
    ''' TLS pseudo-random function as defined in RFC 2246
        splits the secret and return an XOR of their expanded hashes '''
    s1 = secret[:len(secret) // 2 + len(secret) % 2]
    s2 = secret[len(secret) // 2:]

    p_md5 = P_hash(s1, seed, hashlib.md5(used_for_security=Depends), length)  # type: ignore
    p_sha = P_hash(s2, seed, hashlib.sha1, length)

    return strxor(p_md5, p_sha)


def get_mppe_keys(master: bytes, client_random: bytes, server_random: bytes, label: bytes, ssl_connection: SSL.Connection) -> List[bytes]:
    ''' Generate MS-MPPE-Send/Recv-Key as defined in RFC 2548
    On newer OpenSSLs, to support TLS 1.2, randomness is now generated
    via export_keying_material. See T39616 for details. '''
    if SSL.OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_101:
        randomstuff = ssl_connection.export_keying_material(label, 64)
    else:
        label += client_random
        label += server_random
        randomstuff = PRF(master, label, 64)

    return [randomstuff[:32], randomstuff[32:64]]


def encrypt_mppe(plain: bytes, secret: bytes, auth: bytes, salt: bytes) -> bytes:
    ''' encrypt MPPE keys using method described in RFC 2548 2.4.2 '''
    plainlen = len(plain)
    plain = bytes([plainlen]) + plain  # Add Key-Len

    C = b''
    b = hashlib.md5(secret + auth + salt, used_for_security=Depends).digest()  # type: ignore
    for p in (plain[x:x + 16] for x in range(0, len(plain), 16)):
        c = strxor(p, b)
        C += c
        b = hashlib.md5(secret + c, used_for_security=Depends).digest()  # type: ignore

    return C


def ms_attr(x: int, string: bytes) -> bytes:
    # 311 = Microsoft, 16/17 = Recv-Key/Send-Key
    tlv = struct.pack('>IBB', 311, x, len(string) + 2)
    tlv += string
    return tlv


def add_mppe(reply: AuthPacket, keys: List[bytes], secret: bytes, auth: bytes) -> None:
    """
    Add MPPE (Microsoft Point to Point Encryption) attributes to the reply packet

    Args:
        reply (AuthPacket): the reply that will be sent
        keys [bytes, bytes]: two-element list of bytes that are the MPPE keys
        secret (bytes): the RADIUS secret
        auth (bytes): RADIUS authenticator

    """
    sodiumchloride = _generator.randint(32768, 65535)  # Leftmost bit must be set
    potassiumnitrate = _generator.randint(32768, 65535)  # Leftmost bit must be set
    salt = struct.pack('>H', sodiumchloride)
    salt2 = struct.pack('>H', potassiumnitrate)
    encrypted_keys = [encrypt_mppe(keys[0], secret, auth, salt),
                      encrypt_mppe(keys[1], secret, auth, salt2)]
    reply.AddAttribute(26, ms_attr(17, salt + encrypted_keys[0]))  # Recv-key
    reply.AddAttribute(26, ms_attr(16, salt2 + encrypted_keys[1]))  # Send-Key
