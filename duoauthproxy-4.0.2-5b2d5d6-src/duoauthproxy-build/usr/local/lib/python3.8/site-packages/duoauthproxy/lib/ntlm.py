#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import hashlib
import hmac
import struct
import datetime
import os
import socket
import functools
import abc
from typing import List, Sequence, Tuple, Optional

import ldaptor.md4
from dpkt import Packet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from duoauthproxy.lib.md5_wrapper import Depends

# Negotiate Flags
NTLMSSP_NEGOTIATE_56 = 0x80000000
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
NTLMSSP_NEGOTIATE_128 = 0x20000000
NTLMSSP_R1 = 0x10000000
NTLMSSP_R2 = 0x08000000
NTLMSSP_R3 = 0x04000000
NTLMSSP_NEGOTIATE_VERSION = 0x02000000
NTLMSSP_R4 = 0x01000000
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000
NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
NTLMSSP_R5 = 0x00200000
NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_R6 = 0x00040000
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_R7 = 0x00004000
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000
NTLMSSP_ANONYMOUS = 0x00000800
NTLMSSP_R8 = 0x00000400
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_R9 = 0x00000100
NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080
NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040
NTLMSSP_NEGOTIATE_SEAL = 0x00000020
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_R10 = 0x00000008
NTLMSSP_REQUEST_TARGET = 0x00000004
NTLMSSP_NEGOTIATE_OEM = 0x00000002
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001


class FieldDescriptor(Packet):
    __byte_order__ = '<'
    __hdr__ = (
        ('Len', 'H', 0),
        ('MaxLen', 'H', 0),
        ('BufferOffset', 'L', 0)
    )

    def set(self, position, value):
        """Set the contents of the field descriptor for a given
        field value, starting at the given buffer position. return
        the buffer position to be used by the next field"""
        self.Len = self.MaxLen = len(value)
        self.BufferOffset = position
        return position + self.Len

    def get_field(self, buf):
        return buf[self.BufferOffset:self.BufferOffset + self.Len]


_DefaultFieldDescriptor = FieldDescriptor()


class NTLMVersion(Packet):
    __byte_order__ = '<'
    __hdr__ = (
        ('ProductMajorVersion', 'B', 6),
        ('ProductMinorVersion', 'B', 1),
        ('ProductBuild', 'H', 7600),
        ('_Reserved1', 'H', 0),
        ('_Reserved2', 'B', 0),
        ('NTLMRevisionCurrent', 'B', 0x0F),
    )


_DefaultNTLMVersion = NTLMVersion()


class NTLMMessage(Packet):
    _payload_fields: Sequence[Tuple[str, str]] = ()

    def __len__(self):
        ret = self.__hdr_len__
        for (field_name, desc_name) in self._payload_fields:
            ret += len(getattr(self, field_name))
        return ret

    def __bytes__(self):
        """
        Loop through all the payload fields and do two things
            1. Update the buffer to contain the data
            2. Update the pointers in the headers eg. _DomainNameFields to have the new offset and length
        Now that our headers have the updated information we pack those up as well and prepend it to the payload
        """
        buffer = b''
        buffer_pos = self.__hdr_len__
        for (field_name, desc_name) in self._payload_fields:
            field = getattr(self, field_name)
            desc = FieldDescriptor()
            buffer_pos = desc.set(buffer_pos, field)
            buffer += field
            setattr(self, desc_name, bytes(desc))
        buffer = self.pack_hdr() + buffer
        return buffer

    def unpack(self, buf):
        """
        After we unpack a packet from the buffer all the keys from __hdr__
        and all the keys from _payload_fields are set as attrs on self.

        Note: The underscored fields from __hdr__ don't have actual data.
        Only the payload attrs have the real data. In NTLM many headers are a
        description for how to find the real data inside the payload. If you're
        looking for a specific field you can look for it in the header. It's
        entry in the header will tell you it's length and offset in the payload
        so then you can go find it.
        """
        super(NTLMMessage, self).unpack(buf)
        for (field_name, desc_name) in self._payload_fields:
            desc = FieldDescriptor(getattr(self, desc_name))
            setattr(self, field_name, desc.get_field(buf))


class NegotiateMessage(NTLMMessage):
    __byte_order__ = '<'
    __hdr__ = (
        ('Signature', '8s', b'NTLMSSP\0'),
        ('MessageType', 'L', 1),
        ('NegotiateFlags', 'L', 0),
        ('_DomainNameFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('_WorkstationFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('_Version', '8s', bytes(_DefaultNTLMVersion)),
    )
    DomainName = b''
    Workstation = b''
    _payload_fields = (
        ('DomainName', '_DomainNameFields'),
        ('Workstation', '_WorkstationFields')
    )


class AVPair(Packet):
    AVID_MsvAvEOL = 0
    AVID_MsvAvNbComputerName = 1
    AVID_MsvAvNbDomainName = 2
    AVID_MsvAvDnsComputerName = 3
    AVID_MsvAvDnsDomainName = 4
    AVID_MsvAvDnsTreeName = 5
    AVID_MsvAvFlags = 6
    AVID_MsvAvTimestamp = 7
    AVID_MsAvRestrictions = 8
    AVID_MsvAvTargetName = 9
    AVID_MsvChannelBindings = 10

    __byte_order__ = '<'
    __hdr__ = (
        ('AvId', 'H', 0),
        ('AvLen', 'H', 0)
    )
    Value = b''

    @classmethod
    def unpack_pairs(klass, buf):
        pairs = []
        while True:
            pair = klass(buf)
            pair.data = pair.data[:len(pair)]
            pairs.append(pair)
            if pair.AvId == klass.AVID_MsvAvEOL:
                break
            buf = buf[len(pair):]
        return pairs

    @staticmethod
    def pack_pairs(pairs):
        return b''.join([bytes(pair) for pair in pairs])

    def __len__(self):
        return self.__hdr_len__ + len(self.Value)

    def __bytes__(self):
        self.AvLen = len(self.Value)
        return self.pack_hdr() + self.Value

    def unpack(self, buf):
        super(AVPair, self).unpack(buf)
        self.Value = buf[self.__hdr_len__: self.__hdr_len__ + self.AvLen]


class ChallengeMessage(NTLMMessage):
    __byte_order__ = '<'
    __hdr__ = (
        ('Signature', '8s', b'NTLMSSP\0'),
        ('MessageType', 'L', 2),
        ('_TargetNameFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('NegotiateFlags', 'L', 0),
        ('ServerChallenge', '8s', b'\0' * 8),
        ('_Reserved1', '8s', b'\0' * 8),
        ('_TargetInfoFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('_Version', '8s', bytes(_DefaultNTLMVersion)),
    )
    TargetName = b''
    RawTargetInfo = b''
    _payload_fields = (('TargetName', '_TargetNameFields'),
                       ('RawTargetInfo', '_TargetInfoFields'))
    TargetInfo: List[AVPair] = []

    def unpack(self, buf):
        super(ChallengeMessage, self).unpack(buf)
        if self.RawTargetInfo:
            self.TargetInfo = AVPair.unpack_pairs(self.RawTargetInfo)

    def __bytes__(self):
        self.RawTargetInfo = AVPair.pack_pairs(self.TargetInfo)
        return super(ChallengeMessage, self).__bytes__()


class AuthenticateMessage(NTLMMessage):
    __byte_order__ = '<'
    __hdr__ = (
        ('Signature', '8s', b'NTLMSSP\0'),
        ('MessageType', 'L', 3),
        ('_LmChallengeResponseFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('_NtChallengeResponseFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('_DomainNameFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('_UserNameFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('_WorkstationFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('_EncryptedRandomSessionKeyFields', '8s', bytes(_DefaultFieldDescriptor)),
        ('NegotiateFlags', 'L', 0),
        ('Version', '8s', bytes(_DefaultNTLMVersion)),
        ('MIC', '16s', b'\0' * 16),
    )

    LmChallengeResponse = b''
    NtChallengeResponse = b''
    DomainName = b''
    UserName = b''
    Workstation = b''
    EncryptedRandomSessionKey = b''
    _payload_fields = (('DomainName', '_DomainNameFields'),
                       ('UserName', '_UserNameFields'),
                       ('Workstation', '_WorkstationFields'),
                       ('LmChallengeResponse', '_LmChallengeResponseFields'),
                       ('NtChallengeResponse', '_NtChallengeResponseFields'),
                       ('EncryptedRandomSessionKey', '_EncryptedRandomSessionKeyFields'))



class LMResponse(Packet):
    __byte_order__ = '<'
    __hdr__ = (
        ('Response', '24s', b'\0' * 24),
    )


class LMv2Response(Packet):
    __byte_order__ = '<'
    __hdr__ = (
        ('Response', '16s', b'\0' * 16),
        ('ChallengeFromClient', '8s', b'\0' * 16)
    )


class NTLMResponse(Packet):
    __byte_order__ = '<'
    __hdr__ = (
        ('Response', '24s', b'\0' * 24),
    )


class NTLMv2ClientChallenge(Packet):
    __byte_order__ = '<'
    __hdr__ = (
        ('RespType', 'B', 1),
        ('HiRespType', 'B', 1),
        ('_Reserved1', 'H', 0),
        ('_Reserved2', 'L', 0),
        ('TimeStamp', 'Q', 0),
        ('ChallengeFromClient', '8s', b'\0' * 8),
        ('_Reserved3', 'L', 0),
    )

    AVPairs: List[AVPair] = []

    def __bytes__(self):
        return self.pack_hdr() + AVPair.pack_pairs(self.AVPairs)

    def unpack(self, buf):
        super(NTLMv2ClientChallenge, self).unpack(buf)
        self.AVPairs = AVPair.unpack_pairs(buf[self.__hdr_len__:])


class NTLMv2Response(Packet):
    __byte_order__ = '<'
    __hdr__ = (
        ('Response', '16s', b'\0' * 24),
    )

    ClientChallenge = b''

    def __bytes__(self):
        return self.pack_hdr() + self.ClientChallenge

    def unpack(self, buf):
        super(NTLMv2Response, self).unpack(buf)
        self.ClientChallenge = buf[self.__hdr_len__:]


class NTLMSSPMessageSignature:
    __byte_order__ = '<'
    __hdr__ = (
        ('Version', 'L', 1),
        ('RandomPad', '4s', b'\0' * 4),
        ('Checksum', '4s', b'\0' * 4),
        ('SeqNum', 'L', 0)
    )


class NTLMSSPMessageSignature_Extended:
    __byte_order__ = '<'
    __hdr__ = (
        ('Version', 'L', 1),
        ('Checksum', '8s', b'\0' * 8),
        ('SeqNum', 'L', 0)
    )


def create_negotiate_msg(domain='', workstation=''):
    flags = (NTLMSSP_NEGOTIATE_VERSION |
             NTLMSSP_REQUEST_TARGET |
             NTLMSSP_NEGOTIATE_NTLM |
             NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
             NTLMSSP_NEGOTIATE_UNICODE |
             NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)

    if domain:
        flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
    if workstation:
        flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

    msg = NegotiateMessage()
    msg.NegotiateFlags = flags
    # We know these encodings are utf-16le because we specifically set the NEGOTIATE_UNICODE flag
    msg.DomainName = domain.encode('utf-16le')
    msg.Workstation = workstation.encode('utf-16le')
    return bytes(msg)


def KXKEY_v2(SessionBaseKey, LmChallengeResponse, ServerChallenge):
    return SessionBaseKey


def get_ntlm_time():
    ntlm_epoch = datetime.datetime(1601, 1, 1, 0, 0, 0)
    td = datetime.datetime.utcnow() - ntlm_epoch
    ntlm_time = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) * 10
    return ntlm_time


def NTOWFv1(password):
    digest = ldaptor.md4.new(password.encode('utf-16le')).digest()
    return digest


def LMOWFv1(password):
    """LMOWFv1 (LanMan One Way Function) generates a DES based key using
    the first 14 characters of a given password.

    1) It uppercases the first 14 characters
    2) Pads with NULL bytes if needed
    3) Encrypts the first half using the hardcoded value 'KGS!@#$%'
    4) Encrypts the second half using the hardcoded value 'KGS!@#$%'
    5) Returns the concatenated result

    See: https://en.m.wikipedia.org/wiki/LAN_Manager

    Args:
        password (str): the password
    Returns:
        bytes: the LM hash

    """
    lm_password = password.upper()
    # Passwords are only allowed to be a subset of the ascii table. See wiki linked above
    lm_password = lm_password.encode('ascii')
    lm_password = lm_password + b'\0' * (14 - len(lm_password))

    des_key = _create_des_key(lm_password[0:7])
    cipher = Cipher(algorithms.TripleDES(des_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    res = encryptor.update(b'KGS!@#$%') + encryptor.finalize()

    des_key = _create_des_key(lm_password[7:14])
    cipher = Cipher(algorithms.TripleDES(des_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    res += encryptor.update(b'KGS!@#$%') + encryptor.finalize()

    return res


def DESL(key, digest):
    """DESL encrypts a response key and digest and returns a challenge response

    Args:
        key (bytes): a NT or LM response key
        digest (bytes): a Server, Client or Server+Client challenge
    Returns:
        bytes: a NT or LM ChallengeResponse
    """
    des_key = _create_des_key(key[0:7])
    cipher = Cipher(algorithms.TripleDES(des_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    res = encryptor.update(digest) + encryptor.finalize()

    des_key = _create_des_key(key[7:14])
    cipher = Cipher(algorithms.TripleDES(des_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    res += encryptor.update(digest) + encryptor.finalize()

    des_key = _create_des_key(key[14:16] + b'\0' * 5)
    cipher = Cipher(algorithms.TripleDES(des_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    res += encryptor.update(digest) + encryptor.finalize()

    return res


def ComputeResponse_v1(NegotiateFlags, ResponseKeyNT, ResponseKeyLM,
                       ServerChallenge, ClientChallenge, Time, TargetInfo):
    if 0:  
        LmChallengeResponse = DESL(ResponseKeyLM, ServerChallenge)
        NtChallengeResponse = b''
    elif (NegotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY):
        challenge_digest = hashlib.md5(ServerChallenge + ClientChallenge, used_for_security=Depends).digest()
        NtChallengeResponse = DESL(ResponseKeyNT, challenge_digest[0:8])
        LmChallengeResponse = ClientChallenge + b'\0' * 16
    else:
        NtChallengeResponse = DESL(ResponseKeyNT, ServerChallenge)
        if 0:  
            LmChallengeResponse = NtChallengeResponse
        else:
            LmChallengeResponse = DESL(ResponseKeyLM, ServerChallenge)
    SessionBaseKey = ldaptor.md4.new(ResponseKeyNT).digest()
    return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey)


def NTOWFv2(password, user, domain):
    key = ldaptor.md4.new(password.encode('utf-16le')).digest()
    return hmac.new(key, (user.upper() + domain).encode('utf-16le'), functools.partial(hashlib.md5, used_for_security=Depends)).digest()


def ComputeResponse_v2(NegotiateFlags, ResponseKeyNT, ResponseKeyLM,
                       ServerChallenge, ClientChallenge, Time, TargetInfo):
    challenge_struct = NTLMv2ClientChallenge(TimeStamp=Time, ChallengeFromClient=ClientChallenge,
                                             AVPairs=TargetInfo)
    temp = bytes(challenge_struct) + b'\0' * 4
    NtProofStr = hmac.new(ResponseKeyNT, ServerChallenge + temp, functools.partial(hashlib.md5, used_for_security=Depends)).digest()
    NtChallengeResponse = NtProofStr + temp
    LmChallengeResponse = (hmac.new(ResponseKeyLM, ServerChallenge + ClientChallenge, functools.partial(hashlib.md5, used_for_security=Depends)).digest()
                           + ClientChallenge)
    SessionBaseKey = hmac.new(ResponseKeyNT, NtProofStr, functools.partial(hashlib.md5, used_for_security=Depends)).digest()
    return (LmChallengeResponse, NtChallengeResponse, SessionBaseKey)


def _create_des_key(key):
    """_create_des_key adds 8 parity bits to a 56-bit des key thus creating a 64-bit des key

    Args:
        key (bytes): a 56 bit key
    Returns:
        bytes: a 64 bit key which contains 8 parity bits
    """
    # prepend the 56-bit key with a null byte and then unpack it as a 8 byte integer
    key_int = struct.unpack('>Q', b'\0' + key)[0]
    key_int_new = 0

    # iterate 8 times working on 7 bits at a time
    for i in range(8):
        # Get the first 7 bits and left binary shift 1 to make 8 bits
        temp = (key_int & 0x7F) << 1

        # Counts the number of ones' and set the newly added parity bit
        temp |= ((_count_ones(temp) ^ 0x1) & 0x1)

        # with our new key, left shift 8 bits and copy over our 7 bits plus its parity
        key_int_new = (key_int_new << 8) | temp

        # with our original key, right binary shift 7 bits to get ready
        # to process the next 7 bits
        key_int >>= 7

    return struct.pack('<Q', key_int_new)


def _count_ones(val):
    """count_ones will return the number of 1 bits of the passed in value

    Args:
        val (int): the value to count the bits on
    Returns:
        int: the number of 1s in val
    """
    count = 0
    while val:
        count += 1
        val &= (val - 1)
    return count


ARC4_IV = [x for x in range(0, 256)]


class _NTLMv2_ARC4:
    def __init__(self, key):
        self.key = key[:256]

        self._keystream = list(ARC4_IV)
        self._ksa()
        self.prga_i = 0
        self.prga_j = 0

    def _ksa(self):
        key_length = len(self.key)

        j = 0
        for i in ARC4_IV:
            j = (j + self._keystream[i] + self.key[i % key_length]) & 0xFF
            self._keystream[i], self._keystream[j] = self._keystream[j], self._keystream[i]

    def encrypt(self, message_bytes):
        encrypted_bytes = []

        # restore PRGA state
        i = self.prga_i
        j = self.prga_j

        for message_byte in message_bytes:
            i = (i + 1) & 0xFF
            j = (j + self._keystream[i]) & 0xFF
            self._keystream[i], self._keystream[j] = self._keystream[j], self._keystream[i]
            keybyte = self._keystream[(self._keystream[i] + self._keystream[j]) & 0xFF]

            encrypted_bytes.append(keybyte ^ message_byte)

        # store PRGA state
        self.prga_i = i
        self.prga_j = j

        return bytes(encrypted_bytes)

    @staticmethod
    def new(key):
        return _NTLMv2_ARC4(key)


def generate_challenge():
    return os.urandom(8)


class NTLMAuth(object):
    """
        This is an abstract base class for NTLM authenticate messages
        use either NTLMv1Auth or NTLMv2Auth depending on the appropriate version
    """
    def __init__(self, challenge_buffer, username, password, domain='',
                 workstation='', client_challenge=None):
        """ NTLM Authentication message creator
        Args:
        (Note: args passed in as strings are meant to remain as strings when set on `self`. For usages outside
        this class encoding to bytes my be necessary)
            challenge_buffer: (bytes) NTLM challenge information that conforms to
                the interface specified in ntlm.ChallengeMessage

            username: (str) Specifying the user to authenticate as

            password: (str) Password to use as authentication for the specified user

            domain: (str) specifying the domain that the authentication
                request is originating from

            workstation: (str) specifying the workstation that the authenticatino
                request is originating from

            client_challenge: (bytes) Optional bytes to append to the negotiation message
                if a client challenge already exists

        Returns:
            An NTLMAuth object capable of creating authenticate messages for
            the NTLM protocol
        """

        # Challenge must be set first so that our domain setting logic
        # can fallback to the domain provided in the challenge if one is not
        # explicitly provided
        self._set_challenge(challenge_buffer)
        if not domain:
            self._set_domain(self._get_challenge_domain())
        else:
            self._set_domain(domain)

        if not client_challenge:
            self.client_challenge = generate_challenge()
        else:
            self.client_challenge = client_challenge

        if not workstation:
            self._set_workstation(socket.gethostname())
        else:
            self._set_workstation(workstation)

        self.username = username
        self.challenge_buffer = challenge_buffer

        self.response = self._compute_response(username, password)

    @abc.abstractmethod
    def _compute_response(self, username, password):
        pass

    def _set_workstation(self, workstation):
        self.workstation = workstation.upper()

    def _is_negotiate_unicode(self):
        return self.challenge.NegotiateFlags & NTLMSSP_NEGOTIATE_UNICODE

    def _get_encoding(self):
        if self._is_negotiate_unicode():
            return 'UTF-16le'

        return 'ascii'

    def _set_challenge(self, challenge_buffer):
        self.challenge_buffer = challenge_buffer
        self.challenge = ChallengeMessage(challenge_buffer)

    def _get_challenge_domain(self):
        for pair in self.challenge.TargetInfo:
            # If a domain was not specified, attempt to infer it from TargetInfo
            if pair.AvId == AVPair.AVID_MsvAvNbDomainName:
                # The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
                # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
                # Note If a TargetInfo AV_PAIR Value is textual, it MUST be encoded in Unicode irrespective of what character set was negotiated (section 2.2.2.1).
                # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
                return pair.Value.decode('utf-16le')

        return ''

    def _set_domain(self, domain):
        if domain:
            self.domain = domain.upper()
        else:
            self.domain = ''

    def _get_time(self):
        return get_ntlm_time()

    def _get_auth_msg(self):
        msg = AuthenticateMessage()
        msg.DomainName = self.domain.upper().encode(self._get_encoding())
        msg.Workstation = self.workstation.upper().encode(self._get_encoding())
        msg.UserName = self.username.encode(self._get_encoding())
        msg.LmChallengeResponse = self.response[0]
        msg.NtChallengeResponse = self.response[1]
        msg.NegotiateFlags = (NTLMSSP_NEGOTIATE_VERSION |
                              NTLMSSP_REQUEST_TARGET |
                              NTLMSSP_NEGOTIATE_NTLM |
                              NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
                              NTLMSSP_NEGOTIATE_UNICODE |
                              NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        return msg

    def get_encoded_msg(self):
        """ Returns an encoded NTLM

        Returns:
            The encoded NTLM message corresponding to the parameters given to
            this object.
        """

        return bytes(self._get_auth_msg())


class NTLMv1Auth(NTLMAuth):
    def _compute_response(self, username, password):
        response_key_LM = LMOWFv1(password)
        response_key_NT = NTOWFv1(password)
        time = self._get_time()
        return ComputeResponse_v1(self.challenge.NegotiateFlags, response_key_NT,
                                  response_key_LM, self.challenge.ServerChallenge,
                                  self.client_challenge, time,
                                  self.challenge.TargetInfo)


class NTLMv2Auth(NTLMAuth):
    def __init__(self, negotiate_buffer, challenge_buffer, username, password,
                 domain='', workstation='', client_challenge=None, session_key=None):
        super(NTLMv2Auth, self).__init__(challenge_buffer, username,
                                         password, domain, workstation,
                                         client_challenge)
        self._set_session_key(session_key)
        self._set_negotiate_buffer(negotiate_buffer)

    def _get_time(self):
        for pair in self.challenge.TargetInfo:
            # If NTLM v2 authentication is used, the client SHOULD send
            # the timestamp in the CHALLENGE_MESSAGE. [MS-NLMP] p.45
            if pair.AvId == AVPair.AVID_MsvAvTimestamp:
                return struct.unpack('<Q', pair.Value)

        return super(NTLMv2Auth, self)._get_time()

    def _compute_response(self, username, password):
        response_key_LM = response_key_NT = NTOWFv2(password, username, self.domain.upper())
        time = self._get_time()
        return ComputeResponse_v2(self.challenge.NegotiateFlags,
                                  response_key_NT, response_key_LM,
                                  self.challenge.ServerChallenge,
                                  self.client_challenge, time,
                                  self.challenge.TargetInfo)

    def _is_key_negotiation(self):
        return self.challenge.NegotiateFlags & NTLMSSP_NEGOTIATE_KEY_EXCH

    def _build_session_key(self):
        if not self._is_key_negotiation():
            session_key = KXKEY_v2(self.response[2], self.response[0],
                                   self.challenge.ServerChallenge)
        elif self.session_key:
            session_key = self.session_key
        else:
            session_key = os.urandom(16)

        return session_key

    def _build_encrypted_key(self, session_key):
        key_exchange_key = KXKEY_v2(self.response[2], self.response[0],
                                    self.challenge.ServerChallenge)

        cipher = _NTLMv2_ARC4.new(key_exchange_key)
        return cipher.encrypt(session_key)

    def _build_MIC(self, msg, session_key):
        return hmac.new(session_key, self.negotiate_buffer + self.challenge_buffer + bytes(msg),
                        functools.partial(hashlib.md5, used_for_security=Depends)).digest()

    def _set_negotiate_buffer(self, negotiate_buffer):
        self.negotiate_buffer = negotiate_buffer

    def _set_session_key(self, session_key):
        self.session_key = session_key

    def _get_auth_msg(self):
        msg = super(NTLMv2Auth, self)._get_auth_msg()
        msg.NegotiateFlags |= NTLMSSP_NEGOTIATE_TARGET_INFO

        if self.challenge.RawTargetInfo:
            # If NTLM v2 authentication is used and the CHALLENGE_MESSAGE
            # contains a TargetInfo field, the client SHOULD NOT send the
            # LmChallengeResponse and SHOULD set t
            # LmChallengeResponseLen and LmChallengeResponseMaxLen fies
            # in the AUTHENTICATE_MESSAGE to zero. [MS-NLMP] p.
            msg.LmChallengeResponse = b'\0' * 24

        session_key = self._build_session_key()

        if self._is_key_negotiation():
            msg.EncryptedRandomSessionKey = self._build_encrypted_key(session_key)

        msg.MIC = self._build_MIC(msg, session_key)

        return msg


def create_authenticate_msg(negotiate_buffer: bytes, challenge_buffer: bytes, username: str,
                            password: str, domain='', workstation='', ntlm_version=1,
                            client_challenge: Optional[bytes] = None, session_key: Optional[bytes] = None):

    """ Creates an authenticate message for the specified version of NTLM

    Args:
        negotiate_buffer: bytes from the step 1 "negotiate" response
        challenge_buffer: bytes which describe the NTLM challenge request
        username: string for the user to log in as
        password: string for the user's password
        domain: (str) windows domain of the machine attempting to auth
        workstation: (str) workstation of the machine attempting to auth
        ntlm_version: either 1 or 2 representing which version of the NTLM protocol should be used
        client_challenge: (optional bytes) array of 8 bytes to use for the NTLM challenge itself.
        session_key: (optional bytes) key to use for the HMAC on this message

    Returns:
        Prepared and HMAC signed NTLM authenticate message which conforms to the
        specified NTLM protocol

    """
    if ntlm_version == 1:
        auth: NTLMAuth = NTLMv1Auth(challenge_buffer, username, password,
                                    domain, workstation, client_challenge)
    elif ntlm_version == 2:
        auth = NTLMv2Auth(negotiate_buffer, challenge_buffer, username,
                          password, domain, workstation, client_challenge,
                          session_key)
    else:
        raise ValueError('Invalid NTLM version specified')

    return auth.get_encoded_msg()
