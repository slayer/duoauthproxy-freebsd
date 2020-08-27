#!/usr/bin/env python
import contextlib
import io
import json
import os
import struct
import sys
import time
import types
import unittest

from twisted.internet import defer
from twisted.internet import endpoints
from twisted.internet import reactor
from twisted.internet.task import Clock
import twisted.trial.unittest

import drpc.v2 as drpc
from drpc.v2.credentials import DrpcCredentials
from tests.base import DrpcTestBase


class Test_make_kwargs(DrpcTestBase):
    def test_no_args(self):
        def func(): pass

        self.assertEqual({}, drpc.net.make_kwargs(func, {}))
        self.assertEqual({}, drpc.net.make_kwargs(func, {'a': 2}))

    def test_args_only(self):
        def func(a, b): pass

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {})
        self.assertEqual(('missing arg', {'args': ['a', 'b']}),
                         cm.exception.args)

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {'a': 2})
        self.assertEqual(('missing arg', {'args': ['b']}),
                         cm.exception.args)

        expected_kwargs = {'a': 2, 'b': 4}
        self.assertEqual(expected_kwargs,
                         drpc.net.make_kwargs(func, {'a': 2, 'b': 4}))

        self.assertEqual(expected_kwargs,
                         drpc.net.make_kwargs(func,
                                              {'a': 2, 'b': 4, 'c': 8}))

    def test_args_and_defaults(self):
        def func(a, b, c=-2, d=-4): pass

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {})
        self.assertEqual(('missing arg', {'args': ['a', 'b']}),
                         cm.exception.args)

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {'a': 2})
        self.assertEqual(('missing arg', {'args': ['b']}),
                         cm.exception.args)

        self.assertEqual({'a': 2, 'b': 4},
                         drpc.net.make_kwargs(func, {'a': 2, 'b': 4}))
        self.assertEqual({'a': 2, 'b': 4, 'c': 8},
                         drpc.net.make_kwargs(func,
                                              {'a': 2, 'b': 4, 'c': 8}))
        self.assertEqual(
            {'a': 2, 'b': 4, 'c': 8, 'd': 16},
            drpc.net.make_kwargs(func, {'a': 2, 'b': 4, 'c': 8, 'd': 16}))
        self.assertEqual(
            {'a': 2, 'b': 4, 'c': 8, 'd': 16},
            drpc.net.make_kwargs(func,
                                 {'a': 2, 'b': 4, 'c': 8, 'd': 16, 'e': 32}))

    def test_args_and_varargs(self):
        def func(a, b, *args): pass

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {})
        self.assertEqual(('missing arg', {'args': ['a', 'b']}),
                         cm.exception.args)

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {'a': 2})
        self.assertEqual(('missing arg', {'args': ['b']}),
                         cm.exception.args)

        expected_kwargs = {'a': 2, 'b': 4}
        self.assertEqual(expected_kwargs,
                         drpc.net.make_kwargs(func, {'a': 2, 'b': 4}))
        self.assertEqual(expected_kwargs,
                         drpc.net.make_kwargs(func,
                                              {'a': 2, 'b': 4, 'c': 8}))

    def test_args_and_keywords(self):
        def func(a, b, **kwargs): pass

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {})
        self.assertEqual(('missing arg', {'args': ['a', 'b']}),
                         cm.exception.args)

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {'a': 2})
        self.assertEqual(('missing arg', {'args': ['b']}),
                         cm.exception.args)

        expected_kwargs = {'a': 2, 'b': 4}
        self.assertEqual(expected_kwargs,
                         drpc.net.make_kwargs(func, {'a': 2, 'b': 4}))
        expected_kwargs = {'a': 2, 'b': 4, 'c': 8}
        self.assertEqual(expected_kwargs,
                         drpc.net.make_kwargs(func,
                                              {'a': 2, 'b': 4, 'c': 8}))

    def test_args_and_defaults_and_keywords(self):
        def func(a, b, c=-2, d=-4, **kwargs): pass

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {})
        self.assertEqual(('missing arg', {'args': ['a', 'b']}),
                         cm.exception.args)

        with self.assertRaises(drpc.CallError) as cm:
            drpc.net.make_kwargs(func, {'a': 2})
        self.assertEqual(('missing arg', {'args': ['b']}),
                         cm.exception.args)

        self.assertEqual({'a': 2, 'b': 4},
                         drpc.net.make_kwargs(func, {'a': 2, 'b': 4}))
        self.assertEqual({'a': 2, 'b': 4, 'c': 8},
                         drpc.net.make_kwargs(func,
                                              {'a': 2, 'b': 4, 'c': 8}))
        self.assertEqual(
            {'a': 2, 'b': 4, 'c': 8, 'd': 16},
            drpc.net.make_kwargs(func, {'a': 2, 'b': 4, 'c': 8, 'd': 16}))
        self.assertEqual(
            {'a': 2, 'b': 4, 'c': 8, 'd': 16, 'e': 32},
            drpc.net.make_kwargs(func,
                                 {'a': 2, 'b': 4, 'c': 8, 'd': 16, 'e': 32}))

    def test_bound_method(self):
        # pylint: disable=E0213
        class Old():
            def f(self_whatever, a, b=-3): pass

        class New():
            def f(self_whatever, a, b=-4): pass

        class OldInlineCallbacks():
            @drpc.inlineCallbacks
            def f(self_whatever, a, b=-3): pass

        class NewInlineCallbacks():
            @drpc.inlineCallbacks
            def f(self_whatever, a, b=-4): pass
        # pylint: enable=E0213

        for cls in (Old, New, OldInlineCallbacks, NewInlineCallbacks):
            obj = cls()
            func = obj.f
            with self.assertRaises(drpc.CallError) as cm:
                drpc.net.make_kwargs(func, {})
            self.assertEqual(('missing arg', {'args': ['a']}),
                             cm.exception.args)
            # Method's self argument is already bound -- caller
            # shouldn't send it, so it's definitely not an error.
            self.assertEqual({'a': 2},
                             drpc.net.make_kwargs(func, {'a': 2}))
            self.assertEqual({'a': 2, 'b': 4},
                             drpc.net.make_kwargs(func, {'a': 2, 'b': 4}))
            self.assertEqual({'a': 2, 'b': 4},
                             drpc.net.make_kwargs(func,
                                                  {'a': 2, 'b': 4, 'c': 8}))
            # The self argument must be ignored, regardless of name.
            self.assertEqual(
                {'a': 2, 'b': 4},
                drpc.net.make_kwargs(func,
                                     {'a': 2, 'b': 4, 'self_whatever': 8}))


class StringTransport(object):
    """
    Super-stripped down twisted.test.proto_helpers.StringTransport
    because twisted.test may not be installed.
    """

    def __init__(self, hostAddress=None, peerAddress=None):
        if hostAddress is not None:
            self.hostAddr = hostAddress
        if peerAddress is not None:
            self.peerAddr = peerAddress
        self.io = io.BytesIO()
        self.disconnecting = False
        self.disconnected = False

    def value(self):
        return self.io.getvalue()

    def write(self, data):
        self.io.write(data)

    def writeSequence(self, data):
        self.io.write(b''.join(data))

    def loseConnection(self):
        self.disconnecting = True


class ErrorTrackingClientProtocol(drpc.ClientProtocol):
    def __init__(self, *args, **kwargs):
        self.errors = []
        super(ErrorTrackingClientProtocol, self).__init__(
            *args, **kwargs)

    def send_early_error(self, error):
        self.errors.append(error)


class ErrorTrackingClientFactory(drpc.ClientFactory):
    protocol = ErrorTrackingClientProtocol


class TestWireFormat(DrpcTestBase):
    """
    Test that servers and clients generate spec-compliant results for
    good and bad input.
    """
    assertAlmostEqual = unittest.TestCase.assertAlmostEqual

    ikey = 'foo'
    skey = b'bar'
    creds = DrpcCredentials(ikey, skey)
    LEN_LEN = 4

    def connect(self, factory_class):
        factory = factory_class(self.creds)
        protocol = factory.buildProtocol('/Test/Foo')
        trans = StringTransport()
        protocol.makeConnection(trans)
        return protocol

    def pack_len(self, byte_seq):
        return struct.pack('!L', len(byte_seq))

    def msg_byte_seqs(self, data_bytes,
                      type_byte=drpc.Protocol.TYPE_JSON):
        """
        Return a sequence of byte strings for a message with the given
        value. Value does not need to be a valid call or response but
        the message will be otherwise correct.
        """
        data_bytes = type_byte + data_bytes
        sig_time = int(time.time())
        sig_bytes = json.dumps({
            'sig': drpc.crypto.sign_message(self.skey, data_bytes, sig_time),
            'time': sig_time,
        }).encode('utf8')
        return [
            self.pack_len(data_bytes),
            data_bytes,
            self.pack_len(sig_bytes),
            sig_bytes,
        ]

    def test_protocol(self):
        """
        Test serialization and signing of messages in the on-wire protocol.
        """
        protocol = self.connect(drpc.ClientFactory)

        msg = {'foo': 'bar', 'baz': 4, 'qux': None}
        expected_wire_msg = protocol.jsonify(msg).encode('utf8')
        the_before_time = int(time.time())
        protocol.send_msg(msg)
        on_the_wire = protocol.transport.value()

        (data_len,) = struct.unpack('!L', on_the_wire[:self.LEN_LEN])
        self.assertEqual(protocol.TYPE_JSON, bytes([on_the_wire[self.LEN_LEN]]))
        data_end = self.LEN_LEN + 1 + data_len - 1
        wire_msg = on_the_wire[5: data_end]
        self.assertEqual(expected_wire_msg, wire_msg)
        self.assertEqual(msg, json.loads(wire_msg))
        sig_begin = data_end + self.LEN_LEN
        sig_len = struct.unpack('!L', on_the_wire[data_end: sig_begin])
        wire_sig = json.loads(on_the_wire[sig_begin:])
        self.assertIsInstance(wire_sig['time'], int)
        self.assertLessEqual(the_before_time, wire_sig['time'])

        expected = drpc.crypto.sign_message(
            self.skey,
            (drpc.Protocol.TYPE_JSON + expected_wire_msg),
            wire_sig['time'])
        self.assertEqual(expected,
                         wire_sig['sig'])

    def test_drpc_hmac_sha256(self):
        self.assertEqual('75c4bc6b40ed96f83e302c36d38f57cc5f624248eba5f2e8c9ecade92d569e3f',
                         drpc.crypto.sign_message(b'foo', b'b\x0Ar' * 100, 4593))

    def test_send_msg_time_offset(self):
        """
        Check that timestamps from send_msg respect time_offset.
        """
        for time_offset in (500, -500):
            protocol = self.connect(drpc.ClientFactory)
            protocol.factory.time_offset = time_offset
            start = time.time()
            protocol.send_msg('"abc"', serialize_obj=False)

            data_bytes = '\x00\x00\x00\x0e\x00"abc"'
            sig_start = len(data_bytes) + 4
            sig = json.loads(protocol.transport.value()[sig_start:])
            self.assertAlmostEqual((sig['time'] - start),
                                   time_offset,
                                   delta=1)

    def test_sig_bad_time(self):
        protocol = self.connect(drpc.ClientFactory)

        data_bytes = b'\x00\x00\x00\x0e\x00{"bar":"baz"}'
        now = int(time.time())
        delta = drpc.crypto.SIG_WINDOW + 1
        for t in (now - delta,
                  now + delta):
            sig = {
                'sig': drpc.crypto.sign_message(self.skey, data_bytes, t),
                'time': t,
            }
            self.assertFalse(protocol.verify_sig(data_bytes, sig, now=now))

    def test_sig_time_offset(self):
        """
        Check that verify_sig respects time_offset.
        """
        for time_offset in (500, -500):
            protocol = self.connect(drpc.ClientFactory)
            protocol.factory.time_offset = time_offset

            data_bytes = b'\x00\x00\x00\x0e\x00{"bar":"baz"}'
            now = int(time.time()) + time_offset
            delta = drpc.crypto.SIG_WINDOW - 1
            for t in (now - delta,
                      now + delta):
                sig = {
                    'sig': drpc.crypto.sign_message(self.skey, data_bytes, t),
                    'time': t,
                }
                self.assertTrue(protocol.verify_sig(data_bytes, sig))

    def assert_server_error(self, byte_seqs, expected,
                            factory_class=drpc.ServerFactory):
        """
        Simulate the protocol receiving some byte sequences and check
        for the expected response.

        * byte_seqs: Sequence of bytestrings to send to the protocol.
        * expected: Expected result of deserializing the message the
          protocol sends in response.
        * factory_class: DRPC factory class to use when creating
          the protocol.
        """
        protocol = self.connect(factory_class)
        for byte_seq in byte_seqs:
            protocol.dataReceived(byte_seq[:3])
            # Split up incoming chunks to test buffering inside the
            # Protocol.
            if len(byte_seq) > 3:
                protocol.dataReceived(byte_seq[3:])
        on_the_wire = protocol.transport.value()
        data_len = struct.unpack('!L', on_the_wire[:self.LEN_LEN])[0]
        self.assertEqual(drpc.Protocol.TYPE_JSON,
                         bytes([on_the_wire[self.LEN_LEN]]))
        data_end = 5 + data_len - 1
        res = json.loads(on_the_wire[5: data_end])
        self.assertEqual(expected, res)

    def assert_client_error(self, byte_seqs, error):
        """
        Simulate the protocol receiving some byte sequences and check
        for the expected error.
        """
        protocol = self.connect(ErrorTrackingClientFactory)
        for byte_seq in byte_seqs:
            protocol.dataReceived(byte_seq[:3])
            # Split up incoming chunks to test buffering inside the
            # Protocol.
            if len(byte_seq) > 3:
                protocol.dataReceived(byte_seq[3:])
        self.assertEqual(b'', protocol.transport.value())
        self.assertEqual([error], protocol.errors)

    def assert_early_error(self, byte_seqs, error):
        """
        Simulate each protocol receiving some byte sequences and check
        for the expected response.
        """
        # Server must send an error response.
        expected = {
            'error': error,
            'error_args': {},
            'result': None,
        }
        self.assert_server_error(byte_seqs, expected)

        # Client must drop the message with no response.
        self.assert_client_error(byte_seqs, error)

    def test_msg_sig_missing_keys(self):
        data_bytes = b'\x00\x00\x00\x0e\x00{"bar":"baz"}'
        sig_time = int(time.time())
        sigs = [
            {
                'sig': drpc.crypto.sign_message(
                    self.skey, data_bytes[self.LEN_LEN:], sig_time),
            },
            {
                'time': sig_time,
            },
        ]
        for sig in sigs:
            sig_bytes = json.dumps(sig).encode()
            byte_seqs = [
                data_bytes,
                self.pack_len(sig_bytes),
                sig_bytes,
            ]
            self.assert_early_error(byte_seqs, 'bad sig')

    def test_msg_wrong_sig(self):
        data_bytes = b'\x00\x00\x00\x0e\x00{"bar":"baz"}'
        sig_time = int(time.time())
        sig = {
            'sig': ('0' * 40),
            'time': sig_time,
        }
        sig_bytes = json.dumps(sig).encode()
        byte_seqs = [
            data_bytes,
            self.pack_len(sig_bytes),
            sig_bytes,
        ]
        self.assert_early_error(byte_seqs, 'bad sig')

    def test_msg_bad_sig_json(self):
        data_bytes = b'\x00\x00\x00\x0e\x00{"bar":"baz"}'
        sig_bytes = b'more fool you!'
        byte_seqs = [
            data_bytes,
            self.pack_len(sig_bytes),
            sig_bytes,
        ]
        self.assert_early_error(byte_seqs, 'bad msg')

    def test_msg_sig_not_dict(self):
        data_bytes = b'\x00\x00\x00\x0e\x00{"bar":"baz"}'
        sig_bytes = b'"foo"'
        byte_seqs = [
            data_bytes,
            self.pack_len(sig_bytes),
            sig_bytes,
        ]
        self.assert_early_error(byte_seqs, 'bad sig')

    def test_msg_bad_data_json(self):
        data_bytes = b'\x00\x00\x00\x0e\x00{"bar::"baz"}'
        sig_time = int(time.time())
        sig_bytes = json.dumps({
            'sig': drpc.crypto.sign_message(self.skey,
                                        data_bytes[self.LEN_LEN:],
                                        sig_time),
            'time': sig_time,
        }).encode()
        byte_seqs = [
            data_bytes,
            self.pack_len(sig_bytes),
            sig_bytes,
        ]
        self.assert_early_error(byte_seqs, 'bad msg')

    def test_msg_unknown_type(self):
        data_bytes = b'\xAA' + json.dumps({}).encode('utf8')
        sig_time = int(time.time())
        sig_bytes = json.dumps({
            'sig': drpc.crypto.sign_message(self.skey, data_bytes, sig_time),
            'time': sig_time,
        }).encode()
        byte_seqs = [
            self.pack_len(data_bytes),
            data_bytes,
            self.pack_len(sig_bytes),
            sig_bytes,
        ]
        self.assert_early_error(byte_seqs, 'bad msg')

    def test_msg_data_too_short(self):
        byte_seqs = self.msg_byte_seqs(b'')
        self.assert_early_error(byte_seqs, 'bad msg')

    def test_response_msg_not_dict(self):
        byte_seqs = self.msg_byte_seqs(b'44')
        self.assert_client_error(byte_seqs, 'bad msg')

    def test_response_msg_without_id(self):
        byte_seqs = self.msg_byte_seqs(json.dumps({}).encode())
        self.assert_client_error(byte_seqs, 'bad msg')

    def test_response_msg_with_unknown_id(self):
        byte_seqs = self.msg_byte_seqs(b'{"id": "foo"}')
        self.assert_client_error(byte_seqs, 'unknown call id')

    def assert_bad_call(self, error, error_args, call):
        byte_seqs = self.msg_byte_seqs(json.dumps(call).encode())
        expected = {
            'error': error,
            'error_args': error_args,
            'result': None,
            'id': call.get('id'),
        }
        self.assert_server_error(byte_seqs, expected)

    def test_call_msg_without_call(self):
        self.assert_bad_call('bad call', {}, {
                'id': 'foo',
                'args': {},
        })

    def test_call_msg_without_id(self):
        self.assert_bad_call('bad call', {}, {
                'call': 'foo',
                'args': {},
        })

    def test_call_msg_with_bad_args(self):
        self.assert_bad_call('bad call', {}, {
                'call': 'ping',
                'id': 'bar',
                'args': 'blargh',
        })

    def test_call_msg_with_bad_call(self):
        self.assert_bad_call('bad call', {}, {
                'call': 12,
                'id': 'bar',
                'args': {},
        })

    def test_call_msg_unknown_call(self):
        self.assert_bad_call('unknown call', {}, {
                'call': 'bar',
                'id': 'foo',
                'args': {},
        })

    def test_call_msg_call_not_dict(self):
        byte_seqs = self.msg_byte_seqs(json.dumps('watch out').encode())
        expected = {
            'error': 'bad call',
            'error_args': {},
            'result': None,
        }
        self.assert_server_error(byte_seqs, expected)

    def test_impl_returns_unserializable_result(self):
        class ServerFactory(drpc.ServerFactory):
            def do_unserializable(self):
                return object()

        byte_seqs = self.msg_byte_seqs(json.dumps({
                    'call': 'unserializable',
                    'id': 'foo',
        }).encode())
        expected = {
            'id': 'foo',
            'error': 'cannot serialize result',
            'error_args': {},
            'result': None,
        }
        self.assert_server_error(byte_seqs, expected,
                                 factory_class=ServerFactory)

    def test_impl_raises_unserializable_error(self):
        class ServerFactory(drpc.ServerFactory):
            def do_unserializable(self):
                raise drpc.CallError(object())

        byte_seqs = self.msg_byte_seqs(json.dumps({
                    'call': 'unserializable',
                    'id': 'foo',
        }).encode())
        expected = {
            'id': 'foo',
            'error': 'cannot serialize error',
            'error_args': {},
            'result': None,
        }
        self.assert_server_error(byte_seqs, expected,
                                 factory_class=ServerFactory)

    def test_zlib_auto_compresses_big_msg(self):
        protocol = self.connect(drpc.ClientFactory)
        limit = 100
        protocol.auto_zlib_min_length = limit

        # JSON encoding adds two bytes quoting the string.
        protocol.send_msg(json.dumps('a' * (limit - 2)), serialize_obj=False)
        # Strip signature data.
        s_out = protocol.transport.value().rsplit(b'{', 1)[0]
        self.assertEqual(protocol.TYPE_ZJSON, bytes([s_out[4]]))
        # Compression will decrease the length of the string even more
        # than the data LT and sig length add to it. For tedious
        # reasons do not assume zlib.compress is a pure function.
        self.assertLess(len(s_out), limit)

    def test_zlib_auto_leaves_small_messages_unchanged(self):
        protocol = self.connect(drpc.ClientFactory)
        limit = 100
        protocol.auto_zlib_min_length = limit

        # JSON encoding adds two bytes quoting the string.
        s_in = 'a' * (limit - 3)
        protocol.send_msg(json.dumps(s_in), serialize_obj=False)
        # Strip signature data.
        s_out = protocol.transport.value().rsplit(b'{', 1)[0]
        self.assertEqual(protocol.TYPE_JSON, bytes([s_out[4]]))
        expected = '\x00\x00\x00d\x00"' + s_in + '"\x00\x00\x00\\'
        self.assertEqual(expected.encode('utf8'), s_out)

    def test_unzlib(self):
        class ServerProtocol(drpc.Protocol):
            def recv_msg(self, msg):
                self.got = msg

        class ServerFactory(drpc.net.BaseFactory):
            protocol = ServerProtocol

        protocol = self.connect(ServerFactory)
        protocol.enable_unzlib = True
        protocol.SIG_WINDOW = sys.maxsize  # Disable timestamp check.
        for b in self.msg_byte_seqs(
                b'x\x9cSJT\x02\x00\x01M\x00\xa6\x00\x00\x00',
                type_byte=ServerProtocol.TYPE_ZJSON):
            protocol.dataReceived(b)
        self.assertEqual('a', protocol.got)

    def test_unzlib_disabled(self):
        # Assumes the factory will be built with enable_unzlib=False
        # (the current default).
        self.assert_server_error(
            byte_seqs=self.msg_byte_seqs(
                b'x\x9cSJT\x02\x00\x01M\x00\xa6\x00\x00\x00',
                type_byte=drpc.ServerProtocol.TYPE_ZJSON,
            ),
            expected={
                'error': 'bad msg',
                'error_args': {},
                'result': None,
            },
            factory_class=drpc.ServerFactory,
        )

    @defer.inlineCallbacks
    def test_streaming_part_numbering(self):
        big_result = ['a' * 2**10, 'b' * 2**10]

        class ServerFactory(drpc.ServerFactory):
            def do_magic(self, call_id, protocol):
                protocol.streaming_max_length = 2**10
                msg_number = 0
                # Copy big result to ensure comparing with a pristine
                # version later.
                calls = (
                    ['aaa', 'bbb'],  # One message.
                    [],         # Should not increase message count.
                    ['ccc'], # One message.
                    list(big_result),  # Increases message count by two.
                )
                for objs in calls:
                    msg_number = protocol.stream_results(
                        call_id, objs, msg_number)
                return {
                    'stream count': msg_number,
                    'foo': 'bar',
                }

        # Set up callbacks and generate a call message.
        streamed = []
        call_id = 'this is a call id'
        client_protocol = self.connect(drpc.ClientFactory)
        d = client_protocol.call(
            call_name='magic',
            call_id=call_id,
            streaming_cb=streamed.append,
        )

        # Send the call message to the server and parse its response.
        server_protocol = self.connect(ServerFactory)
        server_protocol.dataReceived(client_protocol.transport.value())
        client_protocol.dataReceived(server_protocol.transport.value())

        res = yield d
        self.assertEqual(
            {
                'id': call_id,
                'result': {
                    'foo': 'bar',
                    'stream count': 4,
                },
                'error': None,
                'error_args': {},
            },
            res)

        self.assertEqual(
            [{'error': None,
              'error_args': None,
              'id': call_id,
              'result': ['aaa', 'bbb'],
              'streaming': 0},
             {'error': None,
              'error_args': None,
              'id': call_id,
              'result': ['ccc'],
              'streaming': 1},
             {'error': None,
              'error_args': None,
              'id': call_id,
              'result': [big_result[0]],
              'streaming': 2},
             {'error': None,
              'error_args': None,
              'id': call_id,
              'result': [big_result[1]],
              'streaming': 3}],
            streamed)

    @defer.inlineCallbacks
    def test_streaming_part_splitting(self):
        """
        stream_results must output multiple messages when it cannot fit
        all the serialized objects in one, but small objects can share
        a message.
        """
        objs = [
            'a' * 2**9,         # Next object is large so it will split.
            'b' * 2**9, 'c1', 'c2', 'c3', 'c4', 'c5',  # Large and small fit.
            'd' * 2**9,  # Split again.
        ]

        class ServerFactory(drpc.ServerFactory):
            def do_magic(self, call_id, protocol):
                protocol.streaming_max_length = 2**10
                # Copy objs to ensure comparing with a pristine
                # version later.
                streamed = protocol.stream_results(call_id, list(objs), 0)
                return {
                    "and that's a": 'result',
                }

        # Set up callbacks and generate a call message.
        streamed = []
        call_id = 'this is a call id'
        client_protocol = self.connect(drpc.ClientFactory)
        d = client_protocol.call(
            call_name='magic',
            call_id=call_id,
            streaming_cb=streamed.append,
        )

        # Send the call message to the server and parse its response.
        server_protocol = self.connect(ServerFactory)
        server_protocol.dataReceived(client_protocol.transport.value())
        client_protocol.dataReceived(server_protocol.transport.value())

        res = yield d
        self.assertEqual(
            [
                {
                    'error': None,
                    'error_args': None,
                    'streaming': 0,
                    'result': [objs[0]],
                    'id': call_id,
                },
                {
                    'error': None,
                    'error_args': None,
                    'streaming': 1,
                    'result': objs[1:-1],
                    'id': call_id,
                },
                {
                    'error': None,
                    'error_args': None,
                    'streaming': 2,
                    'result': [objs[-1]],
                    'id': call_id,
                },
            ],
            streamed)
        self.assertEqual(
            {
                'id': 'this is a call id',
                'result': {"and that's a": 'result'},
                'error': None,
                'error_args': {},
            },
            res)


class TimeTravelingReactor(object):
    def __init__(self, target):
        self.clock = Clock()
        self.clock.advance(time.time())
        self.initial_reactor = getattr(target, 'reactor')
        self.target = target

    def __enter__(self):
        self.target.reactor = self.clock
        return self.clock

    def __exit__(self, t, value, traceback):
        self.target.reactor = self.initial_reactor


class TestFeatures(DrpcTestBase):
    """
    Test behavior of real clients and servers.
    """
    assertRaises = unittest.TestCase.assertRaises
    assertAlmostEqual = unittest.TestCase.assertAlmostEqual

    ikey = 'foo'
    skey = b'bar'
    creds = DrpcCredentials(ikey, skey)

    class ServerFactory(drpc.ServerFactory):
        state = 99
        parallel_workers = {}

        def __init__(self, *args, **kwargs):
            self.first_worker = defer.Deferred()
            self.first_server = defer.Deferred()

            self.connected_protocol = None

            def set_protocol(protocol):
                self.connected_protocol = protocol
            self.first_server.addCallback(set_protocol)

            super(TestFeatures.ServerFactory, self).__init__(
                *args, **kwargs)

        @defer.inlineCallbacks
        def get_connected_protocol(self):
            if self.connected_protocol is None:
                yield self.first_server
            defer.returnValue(self.connected_protocol)

        def buildProtocol(self, *args, **kwargs):
            protocol = super(TestFeatures.ServerFactory, self).buildProtocol(*args, **kwargs)
            if self.first_server is not None:
                self.first_server.callback(protocol)
                self.first_server = None
            return protocol

        def do_state(self, new_state=None):
            if new_state is not None:
                self.state = new_state
            return self.state

        def do_raises(self, error=None, error_args=None):
            if error:
                raise drpc.CallError(error, error_args)
            else:
                raise Exception('poof')

        @drpc.inlineCallbacks
        def do_parallel_workers(self, protocol, unblock_conn_id=None):
            conn_id = id(protocol)
            if unblock_conn_id:
                d = self.parallel_workers.get(unblock_conn_id)
                if d is None:
                    raise drpc.CallError('bad arg',
                                         {'args': ['unblock_conn_id']})
                else:
                    d.callback(conn_id)
                unblocker = conn_id
            else:
                d = defer.Deferred()
                self.parallel_workers[conn_id] = d
                if self.first_worker is not None:
                    self.first_worker.callback(conn_id)
                    self.first_worker = None
                unblocker = yield d
            defer.returnValue({
                'conn_id': conn_id,
                'unblocker': unblocker,
            })

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestFeatures, self).setUp()
        self.server_factory = self.ServerFactory(self.creds)

        self.path = '\x00/Test/{:d}/{:s}'.format(os.getpid(), self.id())
        self.listener = reactor.listenUNIX(self.path, self.server_factory)
        self.client = yield self.connect_client()
        self.server = yield self.server_factory.get_connected_protocol()

    @defer.inlineCallbacks
    def tearDown(self):
        yield self.listener.stopListening()
        self.client.transport.abortConnection()
        yield super(TestFeatures, self).tearDown()

    @defer.inlineCallbacks
    def connect_client(self):
        endpoint = endpoints.UNIXClientEndpoint(reactor, self.path)
        client_factory = drpc.ClientFactory(self.creds)
        client = yield endpoint.connect(client_factory)
        defer.returnValue(client)

    @defer.inlineCallbacks
    def test_last_rpc(self):
        """
        Verify that last_rpc is maintained.
        """
        # last_rpc defaults to None when no rpc calls have been made yet
        self.assertIsNone(self.server.last_rpc)

        # Validate last_rpc gets updated during any rpc call
        before_rpc = time.time()
        res = yield self.client.call('ping')
        self.assertGreater(self.server.last_rpc, before_rpc)

    @defer.inlineCallbacks
    def test_ping(self):
        """
        In-depth examination of a ping call's result.
        """
        the_before_time = int(time.time())
        res = yield self.client.call('ping')
        self.assertIs(None, res['error'])
        self.assertEqual({}, res['error_args'])
        # Time returned must be after the call started, rounded down
        # to the nearest int.
        self.assertIsInstance(res['result']['time'], int)
        self.assertLessEqual(the_before_time, res['result']['time'])
        self.assertIsInstance(res['id'], str)

    @defer.inlineCallbacks
    def test_state(self):
        """
        Factory can store state between requests and across connections.
        """
        state = yield self.client.c('state')
        self.assertEqual(self.ServerFactory.state, state)
        # test results that aren't dicts:
        self.assertIsInstance(state,
                              type(self.ServerFactory.state))

        new_state = 66
        state = yield self.client.c('state', new_state=new_state)
        self.assertEqual(new_state, state)
        self.assertEqual(new_state, self.server_factory.state)

        client2 = yield self.connect_client()
        res = yield client2.call('state')
        state = res['result']
        self.assertEqual(new_state, state)
        client2.transport.abortConnection()

    @defer.inlineCallbacks
    def test_parallel_connections(self):
        """
        Two parallel connections that interact.
        """
        d = self.client.c('parallel_workers')
        conn_id = yield self.server_factory.first_worker

        client2 = yield self.connect_client()
        res2 = yield client2.c('parallel_workers', unblock_conn_id=conn_id)
        self.assertEqual(res2['conn_id'], res2['unblocker'])
        client2.transport.abortConnection()

        res = yield d
        self.assertNotEqual(res['conn_id'], res2['conn_id'])
        self.assertEqual(res2['conn_id'], res['unblocker'])

    @contextlib.contextmanager
    def assert_raises_call_error(self, error, error_args):
        with self.assertRaises(drpc.CallError) as cm:
            yield
        e = cm.exception
        # Round trip means the objects shouldn't be the same.
        self.assertEqual(error, e.error)
        self.assertIsNot(e.error, error)
        self.assertEqual(error_args, e.error_args)
        self.assertIsNot(error_args, e.error_args)

    @defer.inlineCallbacks
    def test_raises(self):
        """
        Error serialization and de-serialization.
        """
        default_error = 'unknown error'
        default_error_args = {}
        error = 'some message'
        error_args = {
            'foo': 'bar',
            'bar': 768,
        }
        with self.assert_raises_call_error(default_error,
                                           default_error_args):
            yield self.client.c('raises')
        with self.assert_raises_call_error(error, default_error_args):
            yield self.client.c('raises', error=error)
        with self.assert_raises_call_error(error, error_args):
            yield self.client.c('raises',
                                error=error,
                                error_args=error_args)

        res = yield self.client.call('raises')
        expected = {
                'error': default_error,
                'error_args': default_error_args,
                'result': None,
        }
        self.assertTrue(expected.items() <= res.items())

        res = yield self.client.call('raises', {
                'error': error,
        })
        expected = {
                'error': error,
                'error_args': default_error_args,
                'result': None,
        }
        self.assertTrue(expected.items() <= res.items())

        res = yield self.client.call('raises', {
                'error': error,
                'error_args': error_args,
        })
        expected = {
                'error': error,
                'error_args': error_args,
                'result': None,
        }
        self.assertTrue(expected.items() <= res.items())

    @defer.inlineCallbacks
    def test_timeout(self):
        start = reactor.seconds()
        timeout_secs = 6

        with TimeTravelingReactor(drpc.net) as temp_reactor:
            defered_result = self.client.call('parallel_workers',
                                              timeout_secs=timeout_secs)
            temp_reactor.advance(timeout_secs)
            res = yield defered_result
            end = temp_reactor.seconds()

        expected = {
            'error': 'timeout',
            'error_args': {},
            'result': None,
        }
        self.assertTrue(expected.items() <= res.items())
        self.assertAlmostEqual((end - start), timeout_secs, delta=0.1)

    @defer.inlineCallbacks
    def test_handle_unknown_error(self):
        """
        If an unhandled exception is raised during a call then
        ServerProtocol.handle_unknown_error creates the reply message.
        """
        def handle_unknown_error(call, e):
            handled.append(call['id'])
            handled.append(e.args[0])
            return {
                'error': 'xyzzy'
            }

        handled = []
        self.server.handle_unknown_error = handle_unknown_error
        res = yield self.client.call('raises')
        self.assertEqual([res.pop('id'), 'poof'], handled)
        self.assertEqual(
            res,
            {'error_args': {}, 'error': 'xyzzy', 'result': None})

if __name__ == '__main__':
    unittest.main()
