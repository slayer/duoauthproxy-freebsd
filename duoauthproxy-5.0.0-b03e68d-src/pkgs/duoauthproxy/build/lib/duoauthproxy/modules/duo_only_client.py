#
# Copyright (c) 2013 Duo Security
# All Rights Reserved
#

from ..lib import log
from ..lib.base import AuthResult, ClientModule


class Module(ClientModule):
    def __init__(self, config):
        log.msg("Duo Only Client Module Configuration:")
        log.config(config)

    def authenticate(self, username, password, client_ip, pass_through_attrs=None):
        if pass_through_attrs is None:
            pass_through_attrs = {}
        success = True
        return AuthResult(success, "Ignoring primary credentials")
