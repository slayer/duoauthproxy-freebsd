import struct

from .. import log
from .transport_wrapper import BaseEncoder, LengthDecoder, wrap_protocol


class SignSealEncoder(BaseEncoder):
    def encode(self, data):
        encrypted_message, signature = self.context.encrypt(data)
        log.msg("Got signature length {length}", length=len(signature))
        for_wire = (
            struct.pack("!L", len(signature + encrypted_message))
            + signature
            + encrypted_message
        )
        return for_wire


class MessageTooShort(Exception):
    pass


class SignatureLengthNotSet(Exception):
    pass


class SignSealDecoder(LengthDecoder):
    def decode(self, data):
        # According to the SASL RFC the first 4 octets are the
        # length of the message
        # https://tools.ietf.org/html/rfc4422#section-3.7
        # The size of the signature is dependent on the negotiated auth package

        signature_start = self.header_length
        if not self.context.signature_length:
            raise SignatureLengthNotSet()
        signature_end = self.header_length + self.context.signature_length
        message_length = len(data)
        if message_length < signature_end:
            raise MessageTooShort()

        signature = data[signature_start:signature_end]
        encrypted_data = data[signature_end:message_length]
        return self.context.decrypt(encrypted_data, signature)
