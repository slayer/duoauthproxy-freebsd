#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

from io import StringIO
from typing import Dict, Any

import pyrad.dictionary

from duoauthproxy.lib.radius import dictionary

# Attribute that must be passed through, during
# MS-CHAP2 authentication attempts
MS_CHAP2_REQUEST_ATTRS = [
    'MS-CHAP-Challenge',
    'MS-CHAP2-Response',
    'MS-CHAP2-CPW',
    'MS-CHAP-NT-Enc-PW',
]
MS_CHAP2_RESPONSE_ATTRS = [
    'MS-CHAP2-Success',
    'MS-CHAP-Error',
    'MS-CHAP-Domain',
]

# populate dictionary for pyrad
_RADIUS_DICTIONARY = None


def radius_dictionary():
    global _RADIUS_DICTIONARY
    if not _RADIUS_DICTIONARY:
        fp = StringIO(dictionary.RADIUS_ATTRIBUTES)
        _RADIUS_DICTIONARY = pyrad.dictionary.Dictionary(fp)
        fp.close()
    return _RADIUS_DICTIONARY


class RadiusRequest(object):
    """ Mostly just a facade around pyrad AuthPacket """

    def __init__(self, packet, pw_codec='utf-8', client_ip_attr='Calling-Station-Id'):
        self.packet = packet
        self.pw_codec = pw_codec
        self.client_ip_attr = client_ip_attr

    def __getitem__(self, key):
        return self.packet[key]

    def __setitem__(self, key, item):
        self.packet[key] = item

    def __delitem__(self, key):
        del self.packet[key]

    def __contains__(self, key):
        return key in self.packet

    def get_first(self, key):
        """ Return the first radius packet attribute with the given key """
        if key not in self.packet:
            return None
        return self.packet[key][0]

    @property
    def username(self):
        return self.get_first('User-Name')

    @username.setter
    def username(self, val):
        self.packet['User-Name'] = val

    @property
    def password(self):
        enc_password = self.get_first('User-Password')
        if enc_password:
            return self.packet.PwDecrypt(enc_password, self.pw_codec)
        return None

    @password.setter
    def password(self, val):
        self.packet['User-Password'] = self.packet.PwCrypt(val, self.pw_codec)

    @property
    def client_ip(self):
        return self.get_first(self.client_ip_attr)

    @client_ip.setter
    def client_ip(self, ip):
        self.packet[self.client_ip_attr] = ip

    @property
    def id(self):
        return self.packet.id

    @id.setter
    def id(self, val):
        self.packet.id = val

    @property
    def secret(self):
        return self.packet.secret

    @secret.setter
    def secret(self, val):
        self.packet.secret = val


def add_packet_attributes(packet, attrs: Dict[str, Any]):
    """ Add attributes into radius request packet
    Args:
        packet (Packet): packet for attrs to be added to
        attrs: Dictionary that maps attribute name to it's value
            The value can be
            1. Any basic type, integer, string, bytes
            2. A list of a basic types
    """
    for name, value in attrs.items():
        if name not in packet:
            if isinstance(value, list):
                for v in value:
                    add_single_attr_to_packet(packet, name, v)
            else:
                add_single_attr_to_packet(packet, name, value)


def add_single_attr_to_packet(packet, attr_name: str, attr_value: Any):
    """ Add single attributes into radius request packet
    Args:
        packet (Packet): packet for attrs to be added to
        attr_name (str): Name of the attribute
        attr_value (Any): The value for the attribute not in list form
    """
    if isinstance(attr_value, str):
        attr_value = attr_value.encode('utf8')
    packet.AddAttribute(attr_name, attr_value)
