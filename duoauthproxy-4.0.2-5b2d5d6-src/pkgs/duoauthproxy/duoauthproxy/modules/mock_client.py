#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import copy

from ..lib import log
from ..lib.base import AuthResult, ClientModule


class Module(ClientModule):
    def __init__(self, config):
        log.msg('Mock Client Module Configuration:')
        log.config(config, lambda x: x == 'password')
        self.username = config.get_str('username')
        self.password = config.get_str('password')

        # Read in CHAP2 values which, if sent, are returned as SUCCESS
        self.chap_challenge = config.get_str('chap_challenge', '')
        self.chap2_response = config.get_str('chap2_response', '')

        # CHAP2 value which, if seen in MS-CHAP2-Response, generates
        # a REJECT / Password Expired result
        self.chap2_response_expired = config.get_str('chap2_expired', '')

        # CHAP2 Change Password attribute value that will generate
        # Access Accept, all other values generate Access Reject
        self.chap2_cpw = config.get_str('chap2_cpw', '')

        self.pass_through_radius_attrs = {}

    def authenticate(self, username, password, client_ip, radius_attrs=None):
        if radius_attrs is None:
            radius_attrs = {}
        success = False
        if username == self.username:
            if password is not None and password == self.password:
                success = True
            elif (radius_attrs.get('MS-CHAP-Challenge') == [self.chap_challenge.encode()] and
                    radius_attrs.get('MS-CHAP2-Response') == [self.chap2_response.encode()]):
                success = True
            elif ('MS-CHAP2-CPW' in radius_attrs and
                    radius_attrs.get('MS-CHAP2-CPW') == [self.chap2_cpw.encode()]):
                success = True

        log.msg('auth for \'%s\', \'%s\': %s' % (username, password, success))
        auth_result = AuthResult(success, 'Hello')

        pass_through_attrs = copy.copy(self.pass_through_radius_attrs)

        # Include error info in response, if it's MS-CHAP2 and an error
        if not success and self.chap_challenge:
            pass_through_attrs['MS-CHAP-Error'] = [b'\x00E=691 R=0 V=3']
        if radius_attrs.get('MS-CHAP2-Response') == [self.chap2_response_expired.encode()]:
            pass_through_attrs['MS-CHAP-Error'] = [b'\x00E=648 R=0 V=3']

        if pass_through_attrs:
            auth_result.radius_attrs.update(pass_through_attrs)

        return auth_result
