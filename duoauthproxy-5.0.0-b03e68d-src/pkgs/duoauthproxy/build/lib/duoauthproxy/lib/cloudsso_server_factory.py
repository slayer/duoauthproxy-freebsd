import hashlib
import hmac

import drpc.v2 as drpc

from duoauthproxy import __version__
from duoauthproxy.lib import log
from duoauthproxy.lib.cloudsso_server_protocol import CloudSSOServerProtocol


class CloudSSOServerFactory(drpc.ServerFactory):
    """
    Base class for an Authentication Proxy-specific DRPC Factory.
    """

    protocol = CloudSSOServerProtocol

    def __init__(self, module, **kwargs):
        super(CloudSSOServerFactory, self).__init__(**kwargs)
        self.module = module
        module.register_drpc_call_provider("server_factory", self)

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
        return {"ping": self.do_ping, "identify": self.do_identify}

    def register_new_parameters(self, new_params):
        pass

    def connectionLost(self, reason):
        self.module.restart_looping_call(reason)

    # Calls provided by all Authentication Proxy DRPC modules
    def do_ping(self):
        """
        Perform a DRPC ping operation, but also include the Authentication Proxy version in the reply

        Returns:
            A basic DRPC ping result, with the Authentication Proxy version information added
        """
        info = super(CloudSSOServerFactory, self).do_ping()
        info["version"] = __version__
        return info

    def do_identify(self, challenge):
        return {
            "identities": [
                {
                    "ikey": creds.get_identity(),
                    "sig": hmac.new(
                        creds.get_secret(), challenge.encode("utf-8"), hashlib.sha1
                    ).hexdigest(),
                }
                for creds in self.module.identities.values()
            ],
        }

    # Redirect logging to the standard log module
    def log_msg(self, summary, **kwargs):
        try:
            kwargs = dict(**kwargs)
            log.msg(
                "Summary: {summary}. Extra data: {extra_data}",
                summary=summary,
                extra_data=kwargs,
            )
        except Exception:
            pass

    def log_err(self, stuff, why):
        try:
            # DRPC still logs errors in the old format. (Exception, String Explaining Error)
            # log.failure() can autodetect the exception in flight so we will just log the reason
            log.failure(why)
        except Exception:
            pass

    def log_debug(self, summary, **kwargs):
        if self.module.debug:
            self.log_msg(summary, **kwargs)
