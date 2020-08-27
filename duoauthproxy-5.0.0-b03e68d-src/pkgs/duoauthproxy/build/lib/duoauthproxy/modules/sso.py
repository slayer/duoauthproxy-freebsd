#
# Copyright (c) 2019 Duo Security
# All Rights Reserved
#

import random

from twisted.internet import defer

from duoauthproxy.lib import const, drpc_keys_rotation, duo_async, log, secret_storage
from duoauthproxy.lib.drpc_server_module import DrpcServerModule
from duoauthproxy.lib.duo_creds import DuoCreds


class Module(DrpcServerModule):
    reconnect_interval = 60

    def __init__(self, config):
        super(Module, self).__init__()

        log.msg("CloudSSO Connector Module")

        log.config(
            config,
            (
                lambda k: k
                in (
                    "service_account_password",
                    "service_account_password_protected",
                    "encryption_skey",
                    "encryption_skey_protected",
                    "signing_skey",
                    "signing_skey_protected",
                )
            ),
        )
        self.debug = config.get_bool("debug", False)

        self.duo_creds = DuoCreds(
            identity=config[const.DRPC_PROXY_KEY_IDENTIFIER],
            secret=config[const.DRPC_SIGNING_SKEY_IDENTIFIER].encode(),
        )
        self.host = config[const.DRPC_API_HOST_IDENTIFIER]
        self.encryption_skey = config[const.DRPC_ENCRYPTION_SKEY_IDENTIFIER]

        self.duo_client = self.make_duo_client(
            duo_creds=self.duo_creds,
            host=self.host,
            client_type=duo_async.CloudSSODuoClient,
        )

        self.identities[self.duo_creds.get_identity()] = self.duo_creds

        self.drpc_path = "/drpc/v1/join"

    @defer.inlineCallbacks
    def perform_join(self):
        try:
            server_protocol = yield self.duo_client.proxy_join(
                server_module=self, drpc_path=self.drpc_path
            )
            defer.returnValue(server_protocol)
        except duo_async.DuoAPIRotateRequiredError:
            server_protocol = yield self.rotate_and_rejoin()
            defer.returnValue(server_protocol)
        except duo_async.DuoAPIProxyNotFoundError:
            log.msg("Error connecting to service: Auth Proxy not found")
            self.stopService()
        except duo_async.DuoAPIBadSignatureError:
            log.msg(
                "There was a problem with the Duo API credentials.  If this persists, you may need to reconnect your Authentication Proxy."
            )
            self.stopService()
        except Exception as e:
            log.msg("Exception e: {}".format(e))
            raise e

    @defer.inlineCallbacks
    def rotate_and_rejoin(self):
        new_signing_skey, new_encryption_skey = yield drpc_keys_rotation.rotate_skeys(
            self.duo_client
        )
        self.update_secrets(new_signing_skey, new_encryption_skey)
        # Rebuild the client with the new credentials
        self.duo_client = self.make_duo_client(
            duo_creds=self.duo_creds,
            host=self.host,
            client_type=duo_async.CloudSSODuoClient,
        )

        try:
            server_protocol = yield self.duo_client.proxy_join(
                server_module=self, drpc_path=self.drpc_path
            )
            defer.returnValue(server_protocol)
        except Exception as e:
            log.failure("Failed to rejoin after rotation")
            raise e

    @defer.inlineCallbacks
    def restart_looping_call(self, reason):
        if self._check_connection_lc.running:
            # restart looping call which should trigger a reconnection
            log.msg("Connection lost to SSO: {0}".format(reason))
            self._check_connection_lc.stop()
            yield self._check_connection()
            delay = random.SystemRandom().uniform(1, 60)
            self.reactor.callLater(
                delay, self._check_connection_lc.start, self.reconnect_interval, True
            )

    def update_secrets(
        self, new_signing_skey: bytes, new_encryption_skey: bytes
    ) -> None:
        # Update module's copy
        self.duo_creds = DuoCreds(
            identity=self.duo_creds.get_identity(), secret=new_signing_skey
        )

        # Propagate to interested plugins
        self.register_new_parameters(
            {"signing_skey": new_signing_skey, "encryption_skey": new_encryption_skey}
        )

        # Store in secret storage
        secret_storage.store_secret(
            const.DRPC_SIGNING_SKEY_IDENTIFIER, new_signing_skey.decode("utf-8")
        )
        secret_storage.store_secret(
            const.DRPC_ENCRYPTION_SKEY_IDENTIFIER, new_encryption_skey.decode("utf-8")
        )

    def log_connect(self, rpc_server):
        if rpc_server and rpc_server.transport.connected:
            log.sso_standard(
                msg="sso connection established",
                event_type=log.SSO_EVENT_TYPE_CONNECTIVITY,
                proxy_key=self.duo_creds.identity,
            )

    def log_disconnect(self, rpc_server):
        if rpc_server and rpc_server.transport.disconnected:
            log.sso_standard(
                msg="sso connection disconnected",
                event_type=log.SSO_EVENT_TYPE_CONNECTIVITY,
                proxy_key=self.duo_creds.identity,
            )
