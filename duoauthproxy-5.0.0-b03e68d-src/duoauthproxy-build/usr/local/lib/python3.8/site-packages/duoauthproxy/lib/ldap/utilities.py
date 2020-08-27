import struct
from dataclasses import dataclass
from enum import Enum

import six


class LdapUsernameOrigin(Enum):
    BIND_DN = 1
    NTLM = 2
    RADIUS = 3


class InvalidSid(Exception):
    pass


@dataclass
class LdapUsername:
    """ An object to encapsulate an LDAP username and meta data about that username """

    username: str
    original_location: LdapUsernameOrigin


def convert_binary_sid_to_string(sid):
    """
    Convert a binary data blob containing a sid into the string presentation of a sid
    What is a sid you ask?
        https://blogs.msdn.microsoft.com/larryosterman/2004/09/01/what-is-this-thing-called-sid/
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25

    Args:
        sid with this expected format
            typedef struct _SID {
               BYTE Revision;
               BYTE SubAuthorityCount;
               SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
               DWORD SubAuthority[ANYSIZE_ARRAY];
            } SID, *PISID;

            BYTE is one byte
            SID_IDENTIFIER_AUTHORITY is 8 bytes
            DWORD is 4 bytes
    """
    if not isinstance(sid, six.binary_type):
        raise InvalidSid("Can only convert object sid if its of binary type")

    version, sub_authority_count = struct.unpack("BB", sid[0:2])
    if version != 1:
        # Version 1 is the only sid type that exists today. I don't want to assume this will work for any other version
        # https://blogs.msdn.microsoft.com/larryosterman/2004/09/01/what-is-this-thing-called-sid/
        raise InvalidSid("Unknown object sid format revision {}".format(version))

    # identifier authority is big endian 6 bytes. struct doesn't really have a format for this
    # so we just format big endian 8 bytes. Then we add two zero bytes to the front of our six bytes
    identifier_authority = struct.unpack(">Q", b"\x00\x00" + sid[2:8])[0]

    # Sub Authorities is an array of a size SubAuthorityCount
    # So we can just pull out that many 4 byte integers from the end of the blob
    # This one is little endian formatted.
    sub_authorities = struct.unpack("<" + "L" * sub_authority_count, sid[8:])
    sub_authorities = [six.text_type(x) for x in sub_authorities]

    # Format the sid according to https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25
    full_object_sid = [
        "S",
        six.text_type(version),
        six.text_type(identifier_authority),
    ] + sub_authorities
    return "-".join(full_object_sid)
