#
# Copyright (c) 2013 Duo Security
# All Rights Reserved
#
import base64
import binascii
import collections
import copy
import functools
import hashlib
import hmac
import inspect
import json
import os
import time
import types
import zlib

from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.protocols import basic

import decorator

from . import (
    CallError,
    CallBadArgError,
    CallMissingArgError,
    ERR_BAD_ARG,
    ERR_CONNECTION_LOST,
    ERR_MISSING_ARG,
    ERR_SERIALIZE_RESULT,
    ERR_TIMEOUT,
    ERR_UNKNOWN,
)
from drpc.v2 import crypto


DEFAULT_STREAMING_MAX_LENGTH = 2**19


class Protocol(basic.Int32StringReceiver,
               object):
    MAX_LENGTH = 4 * 2**20      # 4MB. Default is 99,999. WAT.
    jsonify_sort_keys = None

    TYPE_JSON = b'\x00'
    TYPE_BLOB = b'\x01'
    TYPE_ZJSON = b'\x02'

    def __init__(self,
                 enable_unzlib=False,
                 streaming_max_length=DEFAULT_STREAMING_MAX_LENGTH,
                 auto_zlib_min_length=None):
        self.enable_unzlib = enable_unzlib
        self.auto_zlib_min_length = auto_zlib_min_length
        self.streaming_max_length = streaming_max_length

        self.__data_bytes = None
        super(Protocol, self).__init__()

    def jsonify(self, obj):
        """
       Compact JSON serialization.
        """
        return json.dumps(obj,
                          sort_keys=self.jsonify_sort_keys,
                          separators=(',', ':'))

    def send_msg(self, obj, serialize_obj=True):
        """
        JSON-serialize, sign, and send an object.

        * serialize_obj: If False, expect obj to be an
          already-serialized string.
        """
        msg_id = None
        start_msg_time = time.time()
        if serialize_obj:
            msg_id = obj.get('id', None)
            start_jsonify_time = time.time()
            data = self.jsonify(obj)
            self.factory.log_debug(
                'drpc_jsonify_metrics',
                json_parse_time=time.time() - start_jsonify_time,
                length=len(data)
            )
        else:
            data = obj

        data_bytes = self.pack_data(data)

        sig_time = int(time.time())
        sig_time += self.factory.time_offset
        sig_bytes = self.jsonify({
            'sig': crypto.sign_message(self.factory.drpc_creds.get_secret(), data_bytes, sig_time),
            'time': sig_time,
        }).encode()
        self.sendString(data_bytes)
        self.sendString(sig_bytes)
        self.factory.log_debug(
            'drpc_msg_metrics',
            msg_time=time.time() - start_msg_time,
            data_length=len(data_bytes),
            msg_id=msg_id,
        )

    def pack_data(self, data):
        if self.auto_zlib_min_length is not None and (
                len(data) >= self.auto_zlib_min_length):
            start_compression_time = time.time()
            uncompressed_length = len(data)
            data_bytes = self.TYPE_ZJSON + zlib.compress(data.encode())
            self.factory.log_debug(
                'drpc_compression_metrics',
                uncompressed_length=uncompressed_length,
                compressed_length=len(data),
                compression_time=time.time() - start_compression_time)
        else:
            data_bytes = self.TYPE_JSON + data.encode()

        return data_bytes

    def stringReceived(self, string):
        """
        Buffer or parse string depending on whether the complete
        message has been received.
        """
        # Used to use StatefulStringProtocol but it clobbers self.state.
        if self.__data_bytes is None:
            # Expect to read the data LV string.
            self.proto_init(string)
        else:
            # Expect to read the sig LV string.
            self.proto_sig(string)

    def lengthLimitExceeded(self, length):
        # Assume out-of-sync and close the connection.
        self.factory.log_msg('Message with length {0:d} > MAX_LENGTH received.'
                             .format(length))
        self.transport.loseConnection()

    def proto_init(self, data_bytes):
        """
        Stash data_bytes and wait for sig_bytes.
        """
        self.__data_bytes = data_bytes

    @defer.inlineCallbacks
    def proto_sig(self, sig_bytes):
        """
        De-serialize signature object and the already-received data
        object. Verify signature. Call send_early_error() or
        recv_msg() to respond.
        """
        data_bytes = self.__data_bytes
        self.__data_bytes = None # Whatever else happens, reset LV state.
        try:
            sig = json.loads(sig_bytes)
        except ValueError:
            self.send_early_error('bad msg')
            defer.returnValue(None)

        if not self.verify_sig(data_bytes, sig):
            self.send_early_error('bad sig')
            defer.returnValue(None)

        if len(data_bytes) < 1:
            self.send_early_error('bad msg')
        else:
            msg_type = bytes([data_bytes[0]])
            data_bytes = bytes(data_bytes[1:])
            decompress_duration = None
            call_id = None

            if msg_type == self.TYPE_ZJSON and self.enable_unzlib:
                try:
                    t1 = time.time()
                    data_bytes = zlib.decompress(data_bytes)
                    decompress_duration = int((time.time() - t1) * 1000)
                except zlib.error:
                    self.send_early_error('bad msg')
                    defer.returnValue(None)
                msg_type = self.TYPE_JSON

            if msg_type != self.TYPE_JSON:
                self.send_early_error('bad msg')
            else:
                try:
                    t1 = time.time()
                    msg = json.loads(data_bytes)
                    parse_duration = int((time.time() - t1) * 1000)

                    if isinstance(msg, dict):
                        call_id = msg.get('id')
                    self.factory.log_debug(
                        'drpc_timing', data_length=len(data_bytes),
                        parse_duration=parse_duration,
                        decompress_duration=decompress_duration,
                        call_id=call_id,
                    )
                except ValueError:
                    self.send_early_error('bad msg')
                else:
                    try:
                        yield self.recv_msg(msg)
                    except Exception as e:
                        self.factory.log_err(None, 'unknown error in recv_msg')
        defer.returnValue(None)

    def verify_sig(self, data_bytes, sig, now=None):
        """
        Return True iff the signature is correct.
        """
        if not now:
            now = int(time.time())

        now += self.factory.time_offset
        return crypto.verify_sig(data_bytes, sig, self.factory.drpc_creds, now=now)

    def recv_msg(self, msg):
        """
        Handle a valid incoming message.
        """
        raise NotImplementedError()

    def send_early_error(self, error):
        """
        Called with an error name while de-serializing and
        signature-checking incoming messages.
        """
        raise NotImplementedError()


class ServerProtocol(Protocol):

    def __init__(self, *args, **kwargs):
        super(ServerProtocol, self).__init__(*args, **kwargs)
        self.last_rpc = None

    def send_early_error(self, error):
        """
        Servers send a special error response message with no ID if a
        call message is unintelligible.
        """
        return self.send_msg({
                'error': error,
                'error_args': {},
                'result': None,
        })

    @defer.inlineCallbacks
    def recv_msg(self, call):
        """
        Execute call message and send response.
        """
        if not isinstance(call, dict):
            self.send_early_error('bad call')
            defer.returnValue(None)
        try:
            call_id = call.get('id')
            if call_id is None:
                raise CallError('bad call')

            call_name = call.get('call')
            if call_name is None:
                raise CallError('bad call')
            elif not isinstance(call_name, str):
                raise CallError('bad call')

            func = self.get_func_for_call(call_name)
            if func is None:
                raise CallError('unknown call')

            args = call.get('args', {})
            if not isinstance(args, dict):
                raise CallError('bad call')
            else:
                # Smuggle per-call data into the call.
                args = copy.copy(args)
                args['protocol'] = self
                args['call_id'] = call_id

            kwargs = make_kwargs(func, args)
            self.last_rpc = time.time()
            res = yield func(**kwargs)
        except CallError as e:
            try:
                yield self.send_msg({
                        'id': call_id,
                        'result': None,
                        'error': e.error,
                        'error_args': e.error_args,
                })
            except Exception:
                msg = 'cannot serialize error'
                self.factory.log_err(None, msg)
                yield self.send_msg({
                        'id': call_id,
                        'result': None,
                        'error': msg,
                        'error_args': {},
                })
        except Exception as e:
            reply = self.handle_unknown_error(call, e)
            # Ensure error follows spec even if handle_unknown_error()
            # returned a partial message.
            reply['id'] = call_id
            if reply.get('result') is None:
                reply.setdefault('error', ERR_UNKNOWN)
                reply.setdefault('error_args', {})
                reply.setdefault('result', None)
            yield self.send_msg(reply)
        else:
            try:
                yield self.send_msg({
                        'id': call_id,
                        'error': None,
                        'error_args': {},
                        'result': res,
                })
            except Exception:
                msg = ERR_SERIALIZE_RESULT
                self.factory.log_err(None, msg)
                yield self.send_msg({
                        'id': call_id,
                        'result': None,
                        'error': msg,
                        'error_args': {},
                })

    def handle_unknown_error(self, call, e):
        self.factory.log_err(None, 'unknown error in function')
        return {
            'error': ERR_UNKNOWN,
            'error_args': {},
        }

    def stream_results(self, call_id, objs, msg_number):
        """
        Given a list of objects, serialize and send them in messages each
        no longer than self.streaming_max_length.

        msg_number is that of the first message to send. The next
        message to start with is returned, allowing the caller to
        calculate the msg_number parameter for repeated calls.
        """
        if not objs:
            return msg_number

        buf = []
        buf_len = 0
        # 66 bytes for wrapping with a JSON object, plus the size of
        # the call ID, plus 1 byte for type, plus a little extra for
        # very large message numbers.
        max_buf_len = self.streaming_max_length - len(call_id) - 100

        def send_buf(buf):
            data_bytes = self.jsonify({
                'id': call_id,
                'streaming': msg_number,
                'error': None,
                'error_args': None,
            })
            data_bytes = ''.join((
                data_bytes[:-1],
                ',"result":[',
                ','.join(buf),
                ']}',
            ))
            return self.send_msg(
                serialize_obj=False,
                obj=data_bytes,
            )

        for obj in objs:
            try:
                data_bytes = self.jsonify(obj)
            except Exception as e:
                raise CallError(ERR_SERIALIZE_RESULT)
            data_len = len(data_bytes) + 1  # comma
            if data_len > self.MAX_LENGTH:
                raise CallError('object too large in stream')
            if buf_len + data_len > max_buf_len:
                if buf:
                    send_buf(buf)
                    msg_number += 1
                buf = []
                buf_len = 0
            buf.append(data_bytes)
            buf_len += data_len
        if buf:
            send_buf(buf)
            msg_number += 1
        return msg_number

    def get_func_for_call(self, call_name):
        """
        Return callable object implementing the named call, or None.
        """
        return self.factory.get_func_for_call(call_name)


ClientCallState = collections.namedtuple(
    'ClientCallState', ('d', 'cancel_dc', 'streaming_cb'))


class ClientProtocol(Protocol):
    default_timeout = 60 * 60   # 1h

    def __init__(self, *args, **kwargs):
        super(ClientProtocol, self).__init__(*args, **kwargs)

        # Key: call ID. Value: ClientCallState.
        self.calls = {}

    def send_early_error(self, error):
        """
        Clients don't respond to invalid messages.
        """
        self.factory.log_msg('Invalid message received: ' + error)

    @defer.inlineCallbacks
    def c(self, call_name, **kwargs):
        """
        Wrapper around call() that accepts native Python kwargs and
        raises remote error (if any) as a local CallError.
        """
        res = yield self.call(call_name, kwargs)
        if not isinstance(res, dict):
            raise CallError('bad result')

        error = res.get('error')
        if error is not None:
            raise CallError(error=error, error_args=res.get('error_args'))

        defer.returnValue(res.get('result'))

    def call(self, call_name, args=None, timeout_secs=None, call_id=None,
             streaming_cb=None):
        """
        Create and send a call message. Return Deferred to be called
        with the response message if/when it is received.

        Timeouts or other local error conditions are presented as
        error response messages by the same Deferred.

        * timeout_secs: integer number of seconds or None to use
          self.default_timeout.
        * streaming_cb: If not None, streaming_cb(msg) is called with
          each streaming result received.
        """
        if args is None:
            args = {}

        if timeout_secs is None:
            timeout_secs = self.default_timeout
        if not call_id:
            while True:
                call_id = generate_call_id()
                if call_id not in self.calls:
                    break
        if self.transport.disconnected:
            # May race a superclass's connectionLost.
            return {
                'error': ERR_CONNECTION_LOST,
                'error_args': {},
                'id': call_id,
                'result': None,
            }
        d = defer.Deferred()

        def timeout_handler():
            call_state = self.calls.pop(call_id, None)
            if call_state and not d.called:
                d.callback({
                        'error': ERR_TIMEOUT,
                        'error_args': {},
                        'id': call_id,
                        'result': None,
                })
        self.calls[call_id] = ClientCallState(
            d=d,
            cancel_dc=reactor.callLater(timeout_secs, timeout_handler),
            streaming_cb=streaming_cb,
        )
        self.send_msg({
                'call': call_name,
                'args': args,
                'id': call_id,
        })
        return d

    def recv_msg(self, msg):
        """
        Assume the incoming msg is a response. Find and call its
        Deferred.
        """
        # Call send_early_error() in case a subclass wants the info.
        if not isinstance(msg, dict):
            self.send_early_error('bad msg')
            return
        call_id = msg.get('id')
        if call_id is None:
            self.send_early_error('bad msg')
            return

        call_state = self.calls.get(call_id, None)

        if call_state is None:
            self.send_early_error('unknown call id')
            return

        if call_state.streaming_cb and msg.get('streaming') is not None:
            # If part of an unfinished result stream, queue this
            # message for the caller but wait for more.
            call_state.streaming_cb(msg)
            # Don't time out if parts of the stream keep arriving.
            call_state.cancel_dc.reset()
            return
        else:
            self.calls.pop(call_id, None)
            if call_state.cancel_dc.active():
                call_state.cancel_dc.cancel()
            if not call_state.d.called:
                call_state.d.callback(msg)

    def connectionLost(self, reason):
        calls = tuple(self.calls.items()) # copy
        self.calls.clear()
        for call_id, call_state in calls:
            if not call_state.d.called:
                call_state.d.callback({
                        'error': 'connection lost',
                        'error_args': {},
                        'id': call_id,
                        'result': None,
                })
        super(ClientProtocol, self).connectionLost(reason)


def make_kwargs(func, kwargs):
    """
    If func is callable with a subset of kwargs, return that subset.

    Otherwise, raise CallError.
    """
    if not callable(func):
        raise CallError('unknown call')
    elif isinstance(func, functools.partial):
        if func.keywords:
            partial_kwargs = func.keywords.copy()
            partial_kwargs.update(kwargs)
            kwargs = partial_kwargs
        return make_kwargs(func.func, kwargs)
    elif not (inspect.isfunction(func) or inspect.ismethod(func)):
        return make_kwargs(func.__call__, kwargs)

    try:
        argspec = inspect.getfullargspec(func)
    except (TypeError, ValueError):
        raise CallError('unknown call')

    is_bound_method = inspect.ismethod(func) and func.__self__ is not None
    required_args = argspec.args
    if is_bound_method:
        # Skip self argument for bound methods (not that the below
        # works for unbound methods anyway...).
        required_args = required_args[1:]
    if argspec.defaults:
        required_args = required_args[: -1 * len(argspec.defaults)]
    missing = [k for k in required_args if k not in kwargs]
    if missing:
        raise CallMissingArgError(missing)

    kwargs = copy.copy(kwargs)  # no need for deep copy
    if not argspec.varkw:
        for k in tuple(kwargs):
            if k not in argspec.args:
                kwargs.pop(k)
        if is_bound_method:
            # Method's self arg is already bound. Exclude it from the
            # subset like it's an unknown argument name.
            kwargs.pop(argspec.args[0], None)

    try:
        inspect.getcallargs(func, **kwargs)
    except (TypeError, ValueError) as e:
        raise CallError(ERR_MISSING_ARG)
    else:
        return kwargs


def generate_call_id():
    return binascii.hexlify(os.urandom(16)).decode('utf8')


class BaseFactory(protocol.Factory, object):
    def __init__(self, drpc_creds, time_offset=0,
                 streaming_max_length=DEFAULT_STREAMING_MAX_LENGTH,
                 enable_unzlib=False,
                 auto_zlib_min_length=None,
                 idle_rpc_timeout=600):
        """
        * drpc_creds: Instance of DrpcCredentials. Used for identification
          and signing of messages
        * time_offset: Number of seconds to be added to local times to
          equal current peer time. For example, positive offset in a
          client means server clock is ahead of local time.
        * idle_rpc_timeout: If we don't get any rpc call for
          this number of seconds, it's OK to consider the connection idle
          and closable.  To disable, set to None.
        """
        super(BaseFactory, self).__init__()
        self.time_offset = time_offset
        self.auto_zlib_min_length = auto_zlib_min_length
        self.enable_unzlib = enable_unzlib
        self.streaming_max_length = streaming_max_length
        self.drpc_creds = drpc_creds
        self.idle_rpc_timeout = idle_rpc_timeout

    def buildProtocol(self, *args, **kwargs):
        p = self.protocol(
            auto_zlib_min_length=self.auto_zlib_min_length,
            enable_unzlib=self.enable_unzlib,
            streaming_max_length=self.streaming_max_length,
        )
        p.factory = self
        return p

    def log_err(self, stuff, why):
        pass

    def log_msg(self, summary, **kwargs):
        pass

    def log_debug(self, summary, **kwargs):
        pass


class ServerFactory(BaseFactory):
    """
    Base class for RPC servers. Hang remotely-callable methods here.
    """
    protocol = ServerProtocol

    def get_func_for_call(self, call_name):
        # The default implementation is to look for a `do_<call_name>` method.
        # Subclasses should override this behavior if they want to look up the call functions differently
        return getattr(self, 'do_' + call_name, None)

    def do_ping(self):
        return {
            'time': int(time.time()),
        }


class ClientFactory(BaseFactory):
    protocol = ClientProtocol


def inlineCallbacks(func):
    """
    Like defer.inlineCallbacks but properly preserves func's signature.
    """
    return decorator.FunctionMaker.create(
        func, 'return decorated(%(signature)s)',
        dict(decorated=defer.inlineCallbacks(func)), __wrapped__=func)
