import os
import sys

from twisted.logger import (
    FileLogObserver,
    FilteringLogObserver,
    LegacyLogObserverWrapper,
    LogLevel,
    LogLevelFilterPredicate,
    PredicateResult,
    formatEvent,
    jsonFileLogObserver,
    textFileLogObserver,
)
from twisted.python.logfile import LogFile

from duoauthproxy.lib import config_error, log, util

if not util.is_windows_os():
    # This module is not supported on Windows
    import grp
    import pwd

try:
    from twisted.python import syslog
    import syslog as pySyslog
except ImportError:
    syslog = None


def get_observers(main_config, twistd_user, log_group):
    log_debug = main_config.get_bool("debug", False)
    log_to_file = main_config.get_bool("log_file", False)
    log_stdout = main_config.get_bool("log_stdout", False)
    log_syslog = main_config.get_bool("log_syslog", False)
    log_auth_events = main_config.get_bool("log_auth_events", False)
    log_sso_events = main_config.get_bool("log_sso_events", True)

    # Log to file if nothing else is turned on
    log_to_file = log_to_file or not (log_to_file or log_syslog or log_stdout)

    log_dir = main_config.get_str("log_dir", "log")
    log_max_size = main_config.get_int("log_max_size", 10 * (1 << 20))
    log_max_files = main_config.get_int("log_max_files", 6)
    if log_max_files == 0:
        # we need to pass None explicitly if we want there to be no limit
        # 0 would just mean no logfiles would get kept...
        log_max_files = None

    observers = []
    if log_to_file:
        log_txt = create_log_file(
            "authproxy.log",
            log_dir,
            log_max_size,
            log_max_files,
            twistd_user,
            log_group,
        )
        text_observer = textFileLogObserver(log_txt)
        text_filter = FilteringLogObserver(text_observer, [only_default_log_predicate])
        observers.append(text_filter)

    if log_stdout:
        stdout_observer = textFileLogObserver(sys.stdout)
        filtered_stdout = FilteringLogObserver(
            stdout_observer, [only_default_log_predicate]
        )
        observers.append(filtered_stdout)

    if log_syslog:
        if syslog is None:
            raise config_error.ConfigError("syslog not supported on Windows")

        facility_dict = {
            "LOG_KERN": pySyslog.LOG_KERN,
            "LOG_USER": pySyslog.LOG_USER,
            "LOG_MAIL": pySyslog.LOG_MAIL,
            "LOG_DAEMON": pySyslog.LOG_DAEMON,
            "LOG_AUTH": pySyslog.LOG_AUTH,
            "LOG_LPR": pySyslog.LOG_LPR,
            "LOG_NEWS": pySyslog.LOG_NEWS,
            "LOG_UUCP": pySyslog.LOG_UUCP,
            "LOG_CRON": pySyslog.LOG_CRON,
            "LOG_SYSLOG": pySyslog.LOG_SYSLOG,
            "LOG_LOCAL0": pySyslog.LOG_LOCAL0,
            "LOG_LOCAL1": pySyslog.LOG_LOCAL1,
            "LOG_LOCAL2": pySyslog.LOG_LOCAL2,
            "LOG_LOCAL3": pySyslog.LOG_LOCAL3,
            "LOG_LOCAL4": pySyslog.LOG_LOCAL4,
            "LOG_LOCAL5": pySyslog.LOG_LOCAL5,
            "LOG_LOCAL6": pySyslog.LOG_LOCAL6,
            "LOG_LOCAL7": pySyslog.LOG_LOCAL7,
        }
        syslog_facilitystr = main_config.get_str("syslog_facility", "LOG_USER")
        syslog_facility = facility_dict.get(syslog_facilitystr, None)
        if syslog_facility is None:
            raise config_error.ConfigError(
                "Unknown syslog_facility: {0}".format(syslog_facilitystr)
            )

        syslog_observer = syslog.SyslogObserver("Authproxy", facility=syslog_facility)
        wrapped_syslog_observer = LegacyLogObserverWrapper(syslog_observer.emit)
        syslog_filtering_observer = FilteringLogObserver(
            wrapped_syslog_observer, [only_default_log_predicate],
        )
        observers.append(syslog_filtering_observer)

    if log_debug:
        debug_predicate = LogLevelFilterPredicate(LogLevel.debug)
        for i, observer in enumerate(observers):
            observers[i] = FilteringLogObserver(observer, [debug_predicate])

    if log_auth_events:
        auth_log_file = create_log_file(
            "authevents.log",
            log_dir,
            log_max_size,
            log_max_files,
            twistd_user,
            log_group,
        )
        auth_observer = jsonFileLogObserver(auth_log_file, "")
        observers.append(FilteringLogObserver(auth_observer, [auth_type_predicate]))

    if log_sso_events:
        sso_log_file = create_log_file(
            "ssoevents.log",
            log_dir,
            log_max_size,
            log_max_files,
            twistd_user,
            log_group,
        )
        sso_observer = jsonFileLogObserver(sso_log_file, "")
        observers.append(FilteringLogObserver(sso_observer, [sso_type_predicate]))

    return observers


def only_default_log_predicate(event):
    """
    Implementor of the predicate interface used in conjunction with the FilteringLogObserver.

    This should detect events that should be directed to the authproxy log file.
    """
    if (
        event.get(log.MSG_TYPE_KEY) != log.MSG_TYPE_SSO
        and event.get(log.MSG_TYPE_KEY) != log.MSG_TYPE_AUTH
    ):
        return PredicateResult.yes

    return PredicateResult.no


def auth_type_predicate(event):
    """
    Implementor of the predicate interface used in conjunction with the FilteringLogObserver.

    This should detect events that should be directed to the auth log file.
    """
    if event.get(log.MSG_TYPE_KEY) == log.MSG_TYPE_AUTH:
        event.pop(log.MSG_TYPE_KEY)
        return PredicateResult.yes

    return PredicateResult.no


def sso_type_predicate(event):
    """
    Implementor of the predicate interface used in conjunction with the FilteringLogObserver.

    This should detect events that should be directed to the sso log file.
    """
    if event.get(log.MSG_TYPE_KEY) == log.MSG_TYPE_SSO:
        event.pop(log.MSG_TYPE_KEY)
        return PredicateResult.yes

    return PredicateResult.no


def create_log_file(filename, directory, max_size, max_files, twistd_user, log_group):
    """Helper function to create twisted LogFiles and set file permissions

    Change the log file permissions to match our service user if one is defined.
    This is needed so that the service can rotate the log files.
    """
    log_file = LogFile(
        filename,
        directory,
        rotateLength=max_size,
        maxRotatedFiles=max_files,
        defaultMode=0o640,
        data_type_text=True,
    )

    if twistd_user is not None:
        uid, gid = _parse_user(twistd_user)
        if log_group:
            gid = _parse_group(log_group)
        os.chown(os.path.join(directory, filename), uid, gid)

    return log_file


def _parse_group(log_group):
    if os.name == "nt":
        raise Exception("This function is not supported on windows")

    row = grp.getgrnam(log_group)
    return row.gr_gid


def _parse_user(user):
    if util.is_windows_os():
        raise Exception("This function is not supported on windows")

    row = None
    try:
        try:
            # attempt to treat the 'user' option as a uid
            uid = int(user)
        except ValueError:
            # if that failed, look up the username and get the associated uid
            row = pwd.getpwnam(user)
        else:
            row = pwd.getpwuid(uid)
    except KeyError:
        print(
            "Warning: user '%s' does not exist - "
            "duoauthproxy will not drop privileges" % user,
            file=sys.stderr,
        )
    if row:
        return (row.pw_uid, row.pw_gid)
    return (None, None)


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
            level_name = level.name if level is not None else u"-"
            log_level = "[{level_name}]".format(level_name=level_name)

            event_text = formatEvent(event)
            event_text = event_text.replace(u"\n", u"\n\t")

            # Pad the level so that regardless of logging level the left
            # edge of the event text is aligned.
            return u"{level: <7} {event_text}\n".format(
                level=log_level, event_text=event_text
            )

        super(LeanLogObserver, self).__init__(outfile, format_event)
