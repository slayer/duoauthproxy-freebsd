# pylint: disable=W0621
# pylint: disable=R0913

# W0621 -- Redifine msg from outer scope
# log.msg used in many other files
# authstandard(msg="",...) also used in many files

# R0913 -- too many arguments
# should join methods into object

import pprint
import socket
from datetime import datetime

from twisted.logger import FileLogObserver, Logger, formatEvent

# Auth statuses
AUTH_ALLOW = "Allow"
AUTH_CHALLENGE = "Challenge"
AUTH_REJECT = "Reject"
AUTH_ERROR = "Error"

# Auth stages
AUTH_PRIMARY = "Primary authentication"
AUTH_SECONDARY = "Secondary authentication"
AUTH_UNKNOWN = "Unknown"
AUTH_ENROLL_MSG = "User is not enrolled. Enrollment link sent."

MSG_TYPE_AUTH = "AUTH"
MSG_TYPE_KEY = "msg_type"
AUTH_VALUES_KEY = "auth_values"
CONN_LOGGER = "connectivity"

MSG_TYPE_SSO = "SSO"
SSO_VALUES_KEY = "sso_values"
SSO_EVENT_TYPE_CONNECTIVITY = "connectivity"
SSO_EVENT_TYPE_LDAP_QUERY = "ldap_query"
SSO_LDAP_QUERY_TYPE_AUTH = "Primary authentication"
SSO_LDAP_QUERY_TYPE_ATTRIBUTE_FETCH = "Fetching user attributes"
SSO_LDAP_QUERY_SUCCEEDED = "succeeded"
SSO_LDAP_QUERY_FAILED = "failed"


class ProxyLogger:
    """ Simple class that will intercept and buffer calls to twisted logging
    facilities until told it is ready - at which point, it will replay them
    all """

    def __init__(self, logger=None):
        if logger is None:
            self._log = Logger()
        else:
            self._log = logger

        self._calls = []
        self._ready = False

    def ready(self):
        """ Start the logger and release the buffered messages."""
        if not self._ready:
            for call in self._calls:
                call[0](*call[1], **call[2])
            self._calls = []
            self._ready = True

    def msg(self, *args, **kwargs):
        if not self._ready:
            self._calls.append((self._log.info, args, kwargs))
            return

        if (len(args) == 1) and (len(kwargs) == 0):
            # This hack is to support old log messages that might contain {} in them.
            # The old log way of logging would log a single string with variables included
            # via a format call. If one of those variables was a set object then you might have
            # something like "{'data'}". The new formatter will see the {} and try to find a variable
            # passed into the logger function called 'data' to fill it with. This is because the first
            # variable to the new logger functions is technically a format string itself. By using
            # a very simple format string and just logging the data we get we can avoid this bug.
            self._log.info("{msg}", msg=args[0])
        else:
            self._log.info(*args, **kwargs)

    def config(self, config, scrub=lambda x: False):
        result = _sanitize_config(config, scrub)
        if not self._ready:
            self._calls.append((self._log.info, ["{result}"], {"result": result}))
        else:
            self._log.info("{result}", result=result)

    def err(self, *args, **kwargs):
        if not self._ready:
            self._calls.append((self._log.error, args, kwargs))
        else:
            self._log.error(*args, **kwargs)

    def failure(self, *args, **kwargs):
        if not self._ready:
            self._calls.append((self._log.failure, args, kwargs))
        else:
            self._log.failure(*args, **kwargs)

    # def debug(self, *args, **kwargs):
    # if not self._ready:
    # self._calls.append((self._log.debug, args, kwargs))
    # else:
    # self._log.debug(*args, **kwargs)

    def auth(self, **kwargs):
        ts = datetime.utcnow().isoformat() + "Z"
        arguments = {
            "timestamp": ts,
            "msg_type": MSG_TYPE_AUTH,
        }
        arguments.update(kwargs)

        if not self._ready:
            self._calls.append((self._log.info, [], arguments))
        else:
            self._log.info(**arguments)

    def auth_standard(
        self,
        msg,
        username,
        auth_stage,
        status,
        client_ip,
        server_section,
        factor=None,
        server_section_ikey=None,
    ):
        """ Wrapper around auth logging to take all of the required arguments """
        self.auth(
            msg=msg,
            username=username,
            auth_stage=auth_stage,
            status=status,
            client_ip=client_ip,
            server_section=server_section,
            server_section_ikey=server_section_ikey,
            factor=factor,
            hostname=socket.gethostname(),
        )

    def sso(self, **kwargs):
        ts = datetime.utcnow().isoformat() + "Z"
        arguments = {
            "timestamp": ts,
            "msg_type": MSG_TYPE_SSO,
        }
        arguments.update(kwargs)

        if not self._ready:
            self._calls.append((self._log.info, [], arguments))
        else:
            self._log.info(**arguments)

    def sso_standard(self, msg, event_type, proxy_key):
        """ Wrapper around sso logging to take all of the required arguments """
        self.sso(
            msg=msg,
            event_type=event_type,
            proxy_key=proxy_key,
            hostname=socket.gethostname(),
        )

    def sso_ldap(
        self, msg, query_type, status, server, port, username, proxy_key, reason=None
    ):
        """ Wrapper around sso logging to take all of the required arguments for an LDAP SIEM log
        Args:
            msg (str): Human readable message describing the event
            query_type (str): explains to Gary which LDAP command we ran. attribute fetch, authenticate, etc.
                              should be one of SSO_LDAP_QUERY_TYPE_*
            status (str): Simple field for success or failure. See: SSO_LDAP_QUERY_SUCCEEDED
            server (str): IP or hostname of the server we tried to use
            port (int): Port we tried to contact the server on
            username (str): Identifying information for the user that tried to auth. May be a username attr or a full dn
            proxy_key (str): Proxy key value. Useful if multiple proxies are connected
            reason (str): Optional field to explain why a certain status was given.
        """
        self.sso(
            msg=msg,
            event_type=SSO_EVENT_TYPE_LDAP_QUERY,
            query_type=query_type,
            status=status,
            server=server,
            port=port,
            username=username,
            proxy_key=proxy_key,
            reason=reason,
            hostname=socket.gethostname(),
        )


def no_op_observer(event):
    """
    An ILogObserver implementation that simply ignores the event

    :param event: The event to ignore
    """
    pass


def _sanitize_config(config, scrub=lambda x: False):
    """
    Sanitize config is used to take a config and remove sensitive fields

    Args:
        config: (dict) an auth proxy config
        scrub: (lambda) lambda that evalulates which fields to scrub

    Returns:
        str: a pretty print string of the sanitized config
    """
    sanitized_config = dict(config)

    def sanitize(key, value):
        sanitized_keys = [
            "skey",
        ]

        if scrub(key):
            if key in sanitized_keys:
                sanitized_length = len(value)
                return "*****[{0}]".format(sanitized_length)
            else:
                return "*****"

        return value

    sanitized_config = dict(
        (key, sanitize(key, value)) for key, value in sanitized_config.items()
    )

    return pprint.pformat(sanitized_config)


class LoggerContainer(object):
    def __init__(self):
        self.loggers = {}

    def get_logger(self, key):
        """Return the appropriate logger object based on the type
        Args:
            key (str): Identifier for the logger
        Returns:
            Logger
        """
        return self.loggers[key]

    def add_logger(self, key, observer=None):
        """Add a twisted Logger to the dictionary
        Args:
            key (str): Identifier for the logger
            observer (ILogObserver): Optional observer to hook up. Will use globalLogPublisher otherwise
        """
        if observer:
            logger = Logger(observer=observer)
        else:
            logger = Logger()
        self.loggers[key] = logger


class LeanLogObserver(FileLogObserver):
    """
    An twisted log observer for "lean" output that provides less clutter by
    just printing the logging level and event message.
    """

    def __init__(self, outfile):
        def format_event(event):
            """
            Formats the given event into text output that just contains the
            logging level and message (no timestamp or namespace).

            Args:
                event (dict): Dict representing the emitted log event

            Returns:
                unicode: Unicode string to be printed in the logs
            """
            level = event.get("log_level", None)
            level_name = level.name if level is not None else "-"
            log_level = "[{level_name}]".format(level_name=level_name)

            event_text = formatEvent(event)
            event_text = event_text.replace("\n", "\n\t")

            # Pad the level so that regardless of logging level the left
            # edge of the event text is aligned.
            return "{level: <7} {event_text}\n".format(
                level=log_level, event_text=event_text
            )

        super(LeanLogObserver, self).__init__(outfile, format_event)


_instance = ProxyLogger()

ready = _instance.ready
msg = _instance.msg
err = _instance.err
error = _instance.err
failure = _instance.failure
# debug = _instance.debug
config = _instance.config
auth = _instance.auth
auth_standard = _instance.auth_standard
sso = _instance.sso
sso_standard = _instance.sso_standard
sso_ldap = _instance.sso_ldap

logger_container = LoggerContainer()
