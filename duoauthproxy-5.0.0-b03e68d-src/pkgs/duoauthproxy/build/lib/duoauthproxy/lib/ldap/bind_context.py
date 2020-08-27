import hashlib
import hmac
import struct
from abc import ABC, abstractmethod
from functools import partial
from typing import Optional, Tuple

from duoauthproxy.lib import fips_manager
from duoauthproxy.lib.ntlm import _NTLMv2_ARC4


class BaseContext(ABC):
    def __init__(self):
        self.signature_length: Optional[int] = None

    @abstractmethod
    def encrypt(self, data):
        raise NotImplementedError()

    @abstractmethod
    def decrypt(self, encrypted_data, signature):
        raise NotImplementedError()


class SSPIContext(BaseContext):
    def __init__(self, client_auth):
        self.client_auth = client_auth

    def encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        encrypted_message, signature = self.client_auth.encrypt(data)
        # The size of the signature is dependent on the negotiated auth package
        # The signature length remain constant so we can safely use the signature length from the
        # the encrypt call for later decrypt calls
        self.signature_length = len(signature)
        return encrypted_message, signature

    def decrypt(self, encrypted_data: bytes, signature: bytes) -> bytes:
        return self.client_auth.decrypt(encrypted_data, signature)


class NTLMContext(BaseContext):
    def __init__(self, session_key):
        self.session_key = session_key
        self.sequence_number = 0
        self.encryptor = None
        self.decryptor = None

        # The sign and seal constant used both on encrypt and decrypt a message
        # Seal key calculation: # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/bf39181d-e95d-40d7-a740-ab4ec3dc363d
        # Signing key calculation: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/524cdccb-563e-4793-92b0-7bc321fce096
        client_seal_magic_constant = (
            b"session key to client-to-server sealing key magic constant\x00"
        )
        server_seal_magic_constant = (
            b"session key to server-to-client sealing key magic constant\x00"
        )

        self.client_sign_magic_constant = (
            b"session key to client-to-server signing key magic constant\x00"
        )
        self.server_sign_magic_constant = (
            b"session key to server-to-client signing key magic constant\x00"
        )

        client_seal_key = hashlib.md5(  # type: ignore
            self.session_key + client_seal_magic_constant, used_for_security=True,
        ).digest()
        self.encryptor = _NTLMv2_ARC4(client_seal_key)

        server_seal_key = hashlib.md5(  # type: ignore
            self.session_key + server_seal_magic_constant, used_for_security=True,
        ).digest()
        self.decryptor = _NTLMv2_ARC4(server_seal_key)

    def encrypt(self, message: bytes) -> Tuple[bytes, bytes]:
        """
        [MS-NLMP] v30.0 v2018-09-12

        3.4.3 Message Confidentiality
        This function seals a message using the signing key, sealing key, and message sequence
        number

        :param message: The message to be sealed (encrypted)
        :return
            encrypted_message: The encrypted message
            signature: The key used to sign the message.
        """

        signing_key = hashlib.md5(  # type: ignore
            self.session_key + self.client_sign_magic_constant, used_for_security=True,
        ).digest()

        checksum = hmac.new(
            signing_key,
            struct.pack("<I", self.sequence_number) + message,
            digestmod=partial(hashlib.md5, used_for_security=True),  # type: ignore
        ).digest()[:8]
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2c3b4689-d6f1-4dc6-85c9-0bf01ea34d9f
        # The version number MUST be  0x00000001
        version = b"\x01\x00\x00\x00"
        signature = version + checksum + struct.pack("<I", self.sequence_number)
        self.signature_length = len(signature)

        # Encrypt the message
        encrypted_message = self.encryptor.update(message)

        self.sequence_number = self.sequence_number + 1

        return encrypted_message, signature

    def decrypt(self, encrypted_message: bytes, signature: bytes) -> bytes:
        """
        [MS-NLMP] v30.0 v2018-09-12

        3.4.3 Message Confidentiality
        This function unseals a message using the signing key, sealing key, and message sequence
        number

        :param
            message: The message to be unsealed (dencrypted)
            signature: The key used to sign the message.
        :return decrypted_message: The decrypted message
        """

        # Grab the checksum from the signature we received.
        # The first four bytes are the version and can be ignored.
        checksum = signature[4:12]
        sequence_number = struct.unpack("<I", signature[12:16])[0]

        decrypted_message = self.decryptor.update(encrypted_message)

        signing_key = hashlib.md5(  # type: ignore
            self.session_key + self.server_sign_magic_constant, used_for_security=True,
        ).digest()

        # we incremented the sequence number when we sent the message. The response
        # sequence number should correspond to the sequence number of the message we sent.
        expected_sequence_number = self.sequence_number - 1

        # Calculate the expected checksum
        expected_checksum = hmac.new(
            signing_key,
            struct.pack("<I", expected_sequence_number) + decrypted_message,
            digestmod=partial(hashlib.md5, used_for_security=True),  # type: ignore
        ).digest()[:8]

        # Make sure the message hasn't been tampered with
        if not hmac.compare_digest(expected_checksum, checksum):
            raise InvalidSignature("Checksums don't match!")

        # Make sure we did not miss any message
        if expected_sequence_number != sequence_number:
            raise InvalidSignature("Sequence number don't match!")

        return decrypted_message


class InvalidSignature(Exception):
    pass


class SignAndSealNotSupported(Exception):
    pass
