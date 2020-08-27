import drpc.v1 as drpc
from duoauthproxy import __version__
from duoauthproxy.lib import log


class DirectorySyncServerFactory(drpc.ServerFactory):
    """
    Base class for an Authentication Proxy-specific DRPC Factory.
    """
    def __init__(self, module, **kwargs):
        super(DirectorySyncServerFactory, self).__init__(**kwargs)
        self.module = module
        module.register_drpc_call_provider('server_factory', self)

    def get_func_for_call(self, call_name):
        """
        Delegate DRPC call lookups to the module

        Args:
            call_name (str): The DRPC call name

        Returns:
            (function) the function to execute, or None if no such function is found for the requested call name
        """
        return self.module.get_func_for_drpc_call(call_name)

    def get_drpc_calls(self):
        """
        Return the DRPC calls provided by this Factory, that will be common to all Authentication Proxy-based
        DRPC modules

        Returns:
            The call_name -> function lookup for DRPC calls provided by this Factory
        """
        return {
            'ping': self.do_ping,
        }

    def register_new_parameters(self, new_params):
        pass

    # Calls provided by all Authentication Proxy DRPC modules
    def do_ping(self):
        """
        Perform a DRPC ping operation, but also include the Authentication Proxy version in the reply

        Returns:
            A basic DRPC ping result, with the Authentication Proxy version information added
        """
        info = super(DirectorySyncServerFactory, self).do_ping()
        info['version'] = __version__
        return info

    # Redirect logging to the standard log module
    def log_msg(self, summary, **kwargs):
        try:
            kwargs = dict(**kwargs)
            log.msg(summary, kwargs)
        except Exception:
            pass

    def log_err(self, stuff, why):
        try:
            log.err(stuff, why)
        except Exception:
            pass

    def log_debug(self, summary, **kwargs):
        if self.module.debug:
            self.log_msg(summary, **kwargs)
