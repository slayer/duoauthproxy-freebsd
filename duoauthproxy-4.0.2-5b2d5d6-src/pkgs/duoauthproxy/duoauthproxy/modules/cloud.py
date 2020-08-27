#
# Copyright (c) 2013 Duo Security
# All Rights Reserved
#

from twisted.internet import defer

from duoauthproxy.lib import log
from duoauthproxy.lib.drpc_server_module import DrpcServerModule
from duoauthproxy.lib.duo_creds import DuoCreds


class Module(DrpcServerModule):
    def __init__(self, config, _primary_ator=None):
        super(Module, self).__init__()

        log.msg('Cloud Connector Module Configuration:')
        log.config(config, (lambda k: k in (
            'skey',
            'skey_protected',
            'service_account_password',
            'service_account_password_protected',
        )))
        self.debug = config.get_bool('debug', False)
        self.duo_creds = DuoCreds(
            config.get('ikey'),
            config.get_protected_str('skey_protected', 'skey').encode(),
        )

        host = config.get_str('api_host', 'api.duosecurity.com')
        port = config.get_int('api_port', 443)
        self.duo_client = self.make_duo_client(self.duo_creds, host, port=port)

        self.identities[self.duo_creds.get_identity()] = self.duo_creds

        self.drpc_path = '/auth/v2/proxy_join'

    @defer.inlineCallbacks
    def perform_join(self):
        server_protocol = yield self.duo_client.proxy_join(server_module=self, drpc_path=self.drpc_path)
        defer.returnValue(server_protocol)

    def log_connect(self, rpc_server):
        pass

    def log_disconnect(self, rpc_server):
        pass
