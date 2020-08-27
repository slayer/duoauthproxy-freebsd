#!/usr/bin/env python
import base64
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from tests.base import DrpcTestBase

import drpc.v2 as drpc


LOCAL_PRIVATE_KEY = b"""
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBGUbfPWLxjJFfPUItk
ecsNuRRj4l6tkJESG3mXuOqqekbSHR/unm/tm2RyC4avsXKhZANiAARyF+3NuWvX
BrGrLI0/g0RyhG5/hdN2ZxhLaB4NtQ5oF5eDDdugNuzVmBXsy0TdVxuj/36ynMTv
PL3MSiV/ccRUCTPdURJzKC1nk+udrPu+dxHK9gdUeJZGigwrfMEI+lQ=
-----END PRIVATE KEY-----
"""

LOCAL_PUBLIC_KEY = b"""
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEchftzblr1waxqyyNP4NEcoRuf4XTdmcY
S2geDbUOaBeXgw3boDbs1ZgV7MtE3Vcbo/9+spzE7zy9zEolf3HEVAkz3VEScygt
Z5Prnaz7vncRyvYHVHiWRooMK3zBCPpU
-----END PUBLIC KEY-----
"""

REMOTE_PRIVATE_KEY = b"""
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCz05uF5MvigP/zobaz
RhgcSIFGl66PktVIK1Gbvc2pKE4Iunc3E3iEX5wlgW/9G8mhZANiAASyn9FDBaix
QY721GKqcchx/nj+WgumErimiHhpVC6T8hOu1M9vAuuwNyme0OZvMRlL9GjHvVsp
+3U6gyEZIvThV7QRNYGNSPVbg2cGjbS1FjUf6bI8qXXRFiFWcX1zG94=
-----END PRIVATE KEY-----
"""

REMOTE_PUBLIC_KEY = b"""
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEsp/RQwWosUGO9tRiqnHIcf54/loLphK4
poh4aVQuk/ITrtTPbwLrsDcpntDmbzEZS/Rox71bKft1OoMhGSL04Ve0ETWBjUj1
W4NnBo20tRY1H+myPKl10RYhVnF9cxve
-----END PUBLIC KEY-----
"""

BAD_PUBLIC_KEY = b"""
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqcr1OugMcsnyIEGOG7XRb3vVKeLjr2oh
MRnBK17FGNSjWxatNj4yJCeba+K9brkciTzH+Eq6NYoDrLqo3KdyyELtzZK4lGyJ
9aKriETaOldvedTHGoEVFx1NzXsdu838
-----END PUBLIC KEY-----
"""


def generate_keys():
    """
    Generates a public/private key pair and prints them out for use in hard-coded
    deterministic test cases.
    """
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    print(private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.NoEncryption()
    ))
    public_key = private_key.public_key()
    print(public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))


class TestDeriveSecret(DrpcTestBase):
    def test_good_keys(self):
        local_private_key = serialization.load_pem_private_key(
            LOCAL_PRIVATE_KEY,
            password=None,
            backend=default_backend()
        )
        remote_public_key = serialization.load_pem_public_key(
            REMOTE_PUBLIC_KEY,
            backend=default_backend()
        )
        result1 = base64.b64encode(drpc.crypto._compute_ecdh_shared_secret(
            remote_public_key, local_private_key))

        remote_private_key = serialization.load_pem_private_key(
            REMOTE_PRIVATE_KEY,
            password=None,
            backend=default_backend()
        )
        local_public_key = serialization.load_pem_public_key(
            LOCAL_PUBLIC_KEY,
            backend=default_backend()
        )
        result2 = base64.b64encode(drpc.crypto._compute_ecdh_shared_secret(
            local_public_key, remote_private_key))
        self.assertEqual(result1, result2)

    def test_bad_keys(self):
        local_private_key = serialization.load_pem_private_key(
            LOCAL_PRIVATE_KEY,
            password=None,
            backend=default_backend()
        )
        remote_public_key = serialization.load_pem_public_key(
            BAD_PUBLIC_KEY,
            backend=default_backend()
        )
        result1 = base64.b64encode(drpc.crypto._compute_ecdh_shared_secret(
            remote_public_key, local_private_key))

        remote_private_key = serialization.load_pem_private_key(
            REMOTE_PRIVATE_KEY,
            password=None,
            backend=default_backend()
        )
        local_public_key = serialization.load_pem_public_key(
            LOCAL_PUBLIC_KEY,
            backend=default_backend()
        )
        result2 = base64.b64encode(drpc.crypto._compute_ecdh_shared_secret(
            local_public_key, remote_private_key))
        self.assertNotEqual(result1, result2)


class TestDeriveKeys(unittest.TestCase):
    def test_good_keys(self):
        local_private_key = serialization.load_pem_private_key(
            LOCAL_PRIVATE_KEY,
            password=None,
            backend=default_backend()
        )
        remote_public_key = serialization.load_pem_public_key(
            REMOTE_PUBLIC_KEY,
            backend=default_backend()
        )

        signing_key, encryption_key = drpc.crypto.derive_shared_keys(
            remote_public_key, local_private_key)

        self.assertEqual(signing_key,
                         b'eVgiKGRi5vmnXKf2HnFFb5C0u11rzWwvpFpO-0tUNfQ=',
                         'Bad signing key generated'
                         )
        self.assertEqual(encryption_key,
                         b'IXD3u7NeI1hBGzf6C12J3NnLlxvEj9xD8HZRLQ1_cV4=',
                         'Bad encryption key generated'
                         )


class TestKeyGeneration(unittest.TestCase):
    def test_good_generation(self):
        (public, private) = drpc.crypto.generate_ephemeral_keys()
        data = b'bytes to sign'
        sig = private.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        public.verify(sig, data, ec.ECDSA(hashes.SHA256()))

    def test_serialization(self):
        (public, private) = drpc.crypto.generate_ephemeral_keys()
        with self.assertRaises(TypeError):
            private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption
            )

        with self.assertRaises(TypeError):
            private.private_numbers()

        public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )


if __name__ == '__main__':
    unittest.main()
