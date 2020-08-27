import abc
import time

from twisted.internet import defer
from twisted.application.service import Service
from twisted.internet import reactor

from duoauthproxy.lib import duo_async, log
from duoauthproxy.lib.looping_call import LoopingCall


FATAL_ERRORS = [
    40102,  # Invalid integration key in request credentials
    40103,  # Invalid signature
    40112,  # CloudSSO skey expired
    40113,  # Poorly formated public key
    40401,  # Auth Proxy not found
]


class InvalidPlugin(Exception):
    """ Raise when there is an issue registering a plugin. """


class DrpcServerModule(Service, object):
    """
    Base class for an Authentication Proxy-specific module that provides DRPC functionality.
    """
    reconnect_interval = 60

    def __init__(self):
        self.reactor = reactor
        self._check_connection_lc = None
        self.rpc_server = None

        self.identities = {}
        self.call_providers = {}
        self.drpc_calls = {}

    @staticmethod
    def make_duo_client(duo_creds, host, port=443, client_type=duo_async.DirectorySyncDuoClient):
        return client_type(
            host=host,
            duo_creds=duo_creds,
            port=port,
        )

    def get_func_for_drpc_call(self, call_name):
        if call_name in self.drpc_calls:
            return self.drpc_calls[call_name]

        log.err('Unknown DRPC call \'{0}\''.format(call_name))
        return None

    def register_drpc_call_provider(self, provider_id, call_provider):
        """
        Register a DRPC call provider (usually a BaseLdapDrpcPlugin) which has the interface methods
            get_drpc_calls(): dict
            register_new_parameters(dict)
        in order to provide DRPC functionality.

        Plugins are uniquely identified by their provider_id (not object equality).

        Args:
            provider_id (str): A unique identifier for the provider
            call_provider (object): the call provider itself
        """
        # Assert that the provider has the required methods
        required_methods = [
            'get_drpc_calls',
            'register_new_parameters'
        ]
        for method in required_methods:
            if not hasattr(call_provider, method):
                raise InvalidPlugin("DRPC call provider missing required method. Provider id: {}. Method name: {}".format(
                    provider_id, method))

        self.call_providers[provider_id] = call_provider
        self.drpc_calls.update(call_provider.get_drpc_calls())

    def register_new_parameters(self, new_params):
        for provider in self.call_providers.values():
            provider.register_new_parameters(new_params)

    def startService(self):
        super(DrpcServerModule, self).startService()
        self._check_connection_lc = LoopingCall(self._check_connection, clock=self.reactor)
        self._check_connection_lc.start(self.reconnect_interval, True)

    def stopService(self):
        super(DrpcServerModule, self).stopService()
        self._check_connection_lc.stop()
        if self.rpc_server and self.rpc_server:
            self.rpc_server.transport.abortConnection()
            self.rpc_server = None

    @abc.abstractmethod
    @defer.inlineCallbacks
    def perform_join(self):
        """
        Subclasses should implement the logic to perform the join operation to connect to the Duo cloud service

        Returns:
            (ClientProtocol) The twisted protocol for the connection to Duo
        """

    @abc.abstractmethod
    def log_connect(self, rpc_server):
        """
        Subclasses should implement the logic to logging a connect

        Returns: None
        """

    @abc.abstractmethod
    def log_disconnect(self, rpc_server):
        """
        Subclasses should implement the logic to logging a disconnect

        Returns: None
        """

    def is_fatal_error(self, error):
        if isinstance(error, duo_async.DuoAPIError):
            if error.info and 'code' in error.info and error.info['code'] in FATAL_ERRORS:
                return True

        return False

    @defer.inlineCallbacks
    def _check_connection(self):
        disconnected = False
        if not self.rpc_server:
            discon_msg = "no rpc server"
            disconnected = True
        elif self.rpc_server.transport.disconnected:
            discon_msg = "transport disconnected"
            disconnected = True
        elif not self.rpc_server.transport.connected:
            discon_msg = "transport not connected"
            disconnected = True
        elif (self.rpc_server.factory.idle_rpc_timeout is not None and
              self.rpc_server.last_rpc is not None):
            last_rpc = int(time.time() - self.rpc_server.last_rpc)
            if last_rpc > self.rpc_server.factory.idle_rpc_timeout:
                discon_msg = "Missed pings for {0} seconds, maximum {1} seconds allowed.".format(
                    last_rpc, self.rpc_server.factory.idle_rpc_timeout)
                try:
                    # Disconnect the transport just in case.
                    self.rpc_server.transport.abortConnection()
                    log.msg("Connection to Duo service was intentionally closed.")
                except Exception as e:
                    log.msg("Attempted to forcibly disconnect the transport but was unable. Transport likely already disconnected. Exception: {}".format(e))

                disconnected = True

        if disconnected:
            # No connection to service found! Fix that.
            log.msg("DRPC Disconnected: {0}".format(discon_msg))
            log.msg('(Re)connecting to service...')
            # Notify depending on the subclass implementation
            self.log_disconnect(self.rpc_server)

            self.rpc_server = None

            try:
                self.rpc_server = yield self.perform_join()
            except Exception as e:
                if self.is_fatal_error(e):
                    log.msg("Error: {e}".format(e=str(e)))
                    log.msg("This exception requires manual intervention. Stopping service")
                    self.stopService()
                else:
                    log.msg('Error connecting to service: {0}. Will retry again in {1} seconds.'.format(str(e), self.reconnect_interval))
            else:
                self.log_connect(self.rpc_server)
