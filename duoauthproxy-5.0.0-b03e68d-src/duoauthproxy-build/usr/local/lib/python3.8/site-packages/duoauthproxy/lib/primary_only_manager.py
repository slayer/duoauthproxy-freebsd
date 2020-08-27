import sys

from twisted.internet import reactor

from duoauthproxy.lib import log


class PrimaryOnlyManager(object):
    """PrimaryOnlyManager provides the interface that manages running the
    Authentication Proxy in primary only mode. Primary only mode enables
    the Authenticaton Proxy to only perform primary authentication. It will
    not attempt to contact Duo for secondary authentication.
    """

    class __PrimaryOnlyManager(object):
        def __init__(self):
            self._PRIMARY_ONLY_ENABLED = False

        def __str__(self):
            return repr(self) + self._PRIMARY_ONLY_ENABLED

    @staticmethod
    def enable_primary_only(minutes):
        """Enable primary only mode by adding a callback that stops
        the Twisted reactor after a number of minutes

        Args:
            minutes (int): The number of minutes to run in primary only mode before the Authentication Proxy is stopped
        """
        if minutes > 240:
            minutes = 240
        try:

            def primary_only_callback():
                log.msg("Primary only mode has expired. Stopping proxy")
                reactor.stop()

            reactor.callLater(minutes * 60, primary_only_callback)
            log.msg(
                "Running in PRIMARY ONLY mode. Stopping in {0} minutes".format(minutes)
            )
            PrimaryOnlyManager.__instance._PRIMARY_ONLY_ENABLED = True
        except Exception as e:
            log.msg(e)
            print(e)
            sys.exit(2)

    @staticmethod
    def _disable_primary_only():
        """Disables primary only mode.

        This should never be used outside of testing. It also does not stop the proxy from terminating itself.
        """
        PrimaryOnlyManager.__instance._PRIMARY_ONLY_ENABLED = False

    @staticmethod
    def is_primary_only_enabled():
        """Checks if primary mode is enabled

        Returns:
            True if enabled, False otherwise
        """
        return PrimaryOnlyManager.__instance._PRIMARY_ONLY_ENABLED is True

    __instance = __PrimaryOnlyManager()
