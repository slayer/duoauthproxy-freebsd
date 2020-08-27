import struct
from typing import Callable

from duoauthproxy.lib.ldap.bind_context import BaseContext


def wrap_protocol(protocol, encoder_class, decoder_class, context=None):
    # If we don't have a context specified then the protocol may be of
    # interest to the encoder/decoder
    if context is None:
        context = protocol

    protocol.original_data_received = protocol.dataReceived
    decoder = decoder_class(protocol.original_data_received, context)

    protocol.transport.original_write = protocol.transport.write
    encoder = encoder_class(protocol.transport.original_write, context)

    protocol.dataReceived = decoder.dataReceived  # force reads through decoder
    protocol.transport.write = encoder.write  # force writes through encoder


class BaseEncoder:
    def __init__(
        self, write_method: Callable[[bytes], bytes], context: BaseContext = None
    ):
        self.context = context
        self._write = write_method

    def encode(self, data):
        raise NotImplementedError

    def write(self, data):
        self._write(self.encode(data))


class BaseDecoder:
    def __init__(self, callback: Callable[[bytes], bytes], context: BaseContext = None):
        """
        class for wrapping the dataReceived method of a protocol
            - callback (callable): the wrapped protocol's dataRecieved method and the
            - context (BaseContext): should be a subclass of BaseContext contain common functions
        """
        self.context = context
        self.callback = callback
        self.buffer = bytes()

    def dataReceived(self, data):
        # Must call callback with the result of decode
        raise NotImplementedError

    def decode(self, data):
        raise NotImplementedError


class LengthDecoder(BaseDecoder):
    def __init__(
        self, callback, context=None, header_length=4, length_includes_header=False
    ):
        super(LengthDecoder, self).__init__(callback, context)
        self.header_length = header_length
        self.length_includes_header = length_includes_header

    def dataReceived(self, data):
        self.buffer += data

        if len(self.buffer) < self.header_length:
            # we can't even determine the length at this point
            return

        # message_length is the length of signature + encrypted data
        message_length = struct.unpack("!L", self.buffer[: self.header_length])[0]

        # If we don't have the whole message yet, do nothing.
        # buffer should be at least as long as the message length (which is the signature + encrypted data)
        # Start at index 4 since the message length is the first 4 bytes
        if self.length_includes_header:
            buffer_length = len(self.buffer)
        else:
            buffer_length = len(self.buffer[self.header_length :])
        if buffer_length < message_length:
            return

        # We've got the whole message. Decrypt it.
        decoded = self.decode(self.buffer[: message_length + self.header_length])

        # Strip off the message we are ready to decode
        self.buffer = self.buffer[message_length + self.header_length :]
        # Decode data and pass it to the protocol
        self.callback(decoded)
        # Trigger another read in case there is another full message queued
        self.dataReceived(b"")
