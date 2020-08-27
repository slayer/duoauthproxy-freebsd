#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import argparse
import os
import platform
import sys
import warnings

from duoauthproxy.lib import fips_manager, util
from duoauthproxy.lib.radius.server import parse_radius_secrets
from duoauthproxy.lib.primary_only_manager import PrimaryOnlyManager
from duoauthproxy import section


if not util.is_windows_os():
    # This module is not supported on Windows
    import grp
    import pwd


warnings.filterwarnings("ignore",
                        category=DeprecationWarning,
                        message=r"^twisted\.internet\.interfaces\.IStreamClientEndpointStringParser was deprecated in "
                                r"Twisted 14\.0\.0: This interface has been superseded by "
                                r"IStreamClientEndpointStringParserWithReactor\.$")

from twisted.application.service import Application, Service
from twisted.logger import FileLogObserver, FilteringLogObserver, textFileLogObserver, globalLogPublisher, LegacyLogObserverWrapper
from twisted.python.logfile import LogFile
from twisted.python.log import ILogObserver

from .lib import (
    http,
    ssl_verify,
    log,
    forward_serv,
    util,
    config_provider,
    config_error,
    const,
)

try:
    from twisted.python import syslog
    import syslog as pySyslog
except ImportError:
    syslog = None


def get_version():
    import duoauthproxy
    return duoauthproxy.__version__


class LogReadyService(Service):
    """Dumb 'service' whose sole purpose is to print out our version number
    on startup"""

    def startService(self):
        version = get_version()
        log.msg('Duo Security Authentication Proxy %s - Init Complete'
                % version)
        log.ready()
        Service.startService(self)


def create_application(args=None, twistd_user=None, log_group=None):
    home_dir = util.get_home_dir()
    os.chdir(home_dir)
    is_logging_insecure = False

    if syslog is not None:
        facility_dict = {
            'LOG_KERN': pySyslog.LOG_KERN,
            'LOG_USER': pySyslog.LOG_USER,
            'LOG_MAIL': pySyslog.LOG_MAIL,
            'LOG_DAEMON': pySyslog.LOG_DAEMON,
            'LOG_AUTH': pySyslog.LOG_AUTH,
            'LOG_LPR': pySyslog.LOG_LPR,
            'LOG_NEWS': pySyslog.LOG_NEWS,
            'LOG_UUCP': pySyslog.LOG_UUCP,
            'LOG_CRON': pySyslog.LOG_CRON,
            'LOG_SYSLOG': pySyslog.LOG_SYSLOG,
            'LOG_LOCAL0': pySyslog.LOG_LOCAL0,
            'LOG_LOCAL1': pySyslog.LOG_LOCAL1,
            'LOG_LOCAL2': pySyslog.LOG_LOCAL2,
            'LOG_LOCAL3': pySyslog.LOG_LOCAL3,
            'LOG_LOCAL4': pySyslog.LOG_LOCAL4,
            'LOG_LOCAL5': pySyslog.LOG_LOCAL5,
            'LOG_LOCAL6': pySyslog.LOG_LOCAL6,
            'LOG_LOCAL7': pySyslog.LOG_LOCAL7
        }

    # parse command-line args, if appropriate
    primary_only_time = None
    if args:
        option_parser = argparse.ArgumentParser()

        option_parser.add_argument(
            "--primary-only", type=int, nargs='?',
            help="This option disables secondary authentication for the specified number of minutes (default 60)",
            default=None, const=60
        )
        option_parser.add_argument(
            "--logging-insecure",
            action="store_true",
            help="This option enables debug, and prints logs containing passwords and possibly other secrets.",
            default=False
        )
        options = option_parser.parse_args()
        is_logging_insecure = options.logging_insecure
        primary_only_time = options.primary_only

    config_filename = os.path.join('conf', 'authproxy.cfg')
    configuration = config_provider.get_config(config_filename)

    if primary_only_time is not None:
        if primary_only_time > 240:
            print("Primary only mode can only be enabled for a maximum of 4 hours (240 minutes)")
            sys.exit(2)
        else:
            PrimaryOnlyManager.enable_primary_only(primary_only_time)

    main_config = configuration.get_main_section_config()
    if main_config:
        log.msg('Main Configuration:')
        log.config(main_config)

    fips_mode = main_config.get_bool('fips_mode', False)
    if fips_mode:
        fips_manager.enable()

    # handle log configuration
    log_to_file = main_config.get_bool('log_file', False)
    log_stdout = main_config.get_bool('log_stdout', False)
    log_syslog = main_config.get_bool('log_syslog', False)
    log_auth_events = main_config.get_bool('log_auth_events', False)
    log_sso_events = main_config.get_bool('log_sso_events', True)

    if is_logging_insecure:
        globalLogPublisher.addObserver(textFileLogObserver(sys.stdout))
    else:
        if log_to_file or not (log_to_file or log_syslog or log_stdout):
            log_dir = main_config.get_str('log_dir', 'log')
            log_max_size = main_config.get_int('log_max_size', 10 * (1 << 20))
            log_max_files = main_config.get_int('log_max_files', 6)
            if log_max_files == 0:
                # we need to pass None explicitly if we want there to be no limit
                # 0 would just mean no logfiles would get kept...
                log_max_files = None

            log_file = create_log_file('authproxy.log', log_dir, log_max_size,
                                       log_max_files, twistd_user, log_group)
            log_file_observer = textFileLogObserver(log_file)

            if log_auth_events:
                auth_log_file = create_log_file('authevents.log', log_dir, log_max_size, log_max_files, twistd_user, log_group)
                auth_observer = FileLogObserver(auth_log_file, log.format_auth_event)
            else:
                auth_observer = log.no_op_observer

            if log_sso_events:
                sso_log_file = create_log_file('ssoevents.log', log_dir, log_max_size, log_max_files, twistd_user, log_group)
                sso_observer = FileLogObserver(sso_log_file, log.format_sso_event)
            else:
                sso_observer = log.no_op_observer

            auth_filtering_observer = FilteringLogObserver(auth_observer,
                                                           [log.auth_type_predicate],
                                                           log.no_op_observer)

            globalLogPublisher.addObserver(auth_filtering_observer)

            sso_filtering_observer = FilteringLogObserver(sso_observer,
                                                          [log.sso_type_predicate],
                                                          log.no_op_observer)

            globalLogPublisher.addObserver(sso_filtering_observer)

            # the default authproxy.log
            log_file_observer = FilteringLogObserver(log_file_observer,
                                                     [log.only_default_log_predicate],
                                                     log.no_op_observer)

            globalLogPublisher.addObserver(log_file_observer)

        if log_stdout:
            std_out_observer = textFileLogObserver(sys.stdout)
            std_out_filter = FilteringLogObserver(log.no_op_observer,
                                                  [log.auth_type_predicate],
                                                  std_out_observer)
            globalLogPublisher.addObserver(std_out_filter)
        if log_syslog:
            if syslog is None:
                raise config_error.ConfigError('syslog not supported on Windows')
            syslog_facilitystr = main_config.get_str('syslog_facility', 'LOG_USER')
            syslog_facility = facility_dict.get(syslog_facilitystr, None)
            if syslog_facility is None:
                raise config_error.ConfigError('Unknown syslog_facility: {0}'.format(syslog_facilitystr))
            syslog_observer = syslog.SyslogObserver('Authproxy', facility=syslog_facility)
            wrapped_syslog_observer = LegacyLogObserverWrapper(syslog_observer.emit)
            syslog_filtering_observer = FilteringLogObserver(log.no_op_observer,
                                                             [log.auth_type_predicate],
                                                             wrapped_syslog_observer)
            globalLogPublisher.addObserver(syslog_filtering_observer)

    # Global debug mode
    if is_logging_insecure:
        debug_mode = True
    else:
        debug_mode = main_config.get_bool('debug', False)

    http.set_debug(debug_mode)
    http.set_is_logging_insecure(is_logging_insecure)

    # Create main application.
    application = Application('duoauthproxy')
    LogReadyService().setServiceParent(application)

    fips_mode = fips_manager.status()
    if fips_mode:
        log.msg("FIPS mode {0} is enabled with {1}".format(fips_mode, fips_manager.get_openssl_version()))
    else:
        log.msg("FIPS mode is not enabled")

    # get ca certs file
    http_ca_certs_file = main_config.get_str('http_ca_certs_file', '')
    if http_ca_certs_file:
        http_ca_certs_file = util.resolve_file_path(http_ca_certs_file)
    else:
        http_ca_certs_file = os.path.join('conf', const.DEFAULT_HTTP_CERTS_FILE)

    # read ca certs
    if not os.path.isfile(http_ca_certs_file):
        http_ca_certs_file = os.path.join('conf', http_ca_certs_file)
    with open(http_ca_certs_file, 'r') as bundle_fp:
        http.set_ca_certs(ssl_verify.load_ca_bundle(bundle_fp))

    # get proxy settings
    http_proxy_host = main_config.get_str('http_proxy_host', '')
    http_proxy_port = main_config.get_int('http_proxy_port', 80)
    if http_proxy_host:
        http.set_proxy(http_proxy_host, http_proxy_port)

    sections = section.parse_sections(configuration, is_logging_insecure)
    module_factory = section.ModuleFactory(sections, application)
    modules_by_type = module_factory.make_modules()

    if not any(modules_by_type.values()):
        raise config_error.ConfigError('No integrations in config file.')

    # Setup forwarding/server pairs by port
    for port, interface in modules_by_type.get('server', []):
        server_networks = {}
        server_names = {}
        for section_name, server_module, server_config in modules_by_type['server'][(port, interface)]:
            client_name = configuration.get_section_client(section_name)

            if not client_name:
                if server_module.Module.no_client:
                    modules_by_type['client']['no_client'] = None
                    client_name = 'no_client'
                else:
                    raise config_error.ConfigError('Neither module %s or main has "client" value' % section_name)

            if section_name.startswith('ldap_server_auto') and not client_name.startswith('ad_client'):
                raise config_error.ConfigError('ad_client is required by ldap_server_auto. No ad_client found in config file. ')

            if client_name != 'radius_client' \
                    and server_config.get_str('pass_through_attr_names', ''):
                raise config_error.ConfigError('Can only pass through radius attributes if using a radius client')
            server_instance = server_module.Module(server_config,
                                                   modules_by_type['client'][client_name],
                                                   section_name)
            server_instance.setServiceParent(application)

            if section_name.startswith('radius_server_'):
                server_networks[server_instance] = parse_radius_secrets(server_config).keys()
                server_names[server_instance] = section_name

        if server_names:
            forward_module = forward_serv
            forward_instance = forward_module.Module(
                port=port,
                servers=server_networks,
                server_names=server_names,
                interface=interface,
                debug=debug_mode,
            )
            forward_instance.setServiceParent(application)

    # set user-agent
    sections = ','.join(sorted(set(configuration.list_sections())))
    user_agent = "duoauthproxy/{0} ({1}; Python{2}; {3})".format(
        get_version(),
        platform.platform(),
        platform.python_version(),
        sections)
    http.set_user_agent(user_agent)

    # Authproxy uses globalLogPublisher to emit events. Defining a no-op emitter will squelch the creation
    # of the unwatned twistd default logging mechanisms.
    def no_op_emitter(eventDict):
        pass

    application.setComponent(ILogObserver, no_op_emitter)

    return application


def create_log_file(filename, directory, max_size, max_files, twistd_user, log_group):
    """Helper function to create twisted LogFiles and set file permissions

    Change the log file permissions to match our service user if one is defined.
    This is needed so that the service can rotate the log files.
    """
    log_file = LogFile(filename, directory, rotateLength=max_size, maxRotatedFiles=max_files, defaultMode=0o640, data_type_text=True)

    if twistd_user is not None:
        uid, gid = _parse_user(twistd_user)
        if log_group:
            gid = _parse_group(log_group)
        os.chown(os.path.join(directory, filename), uid, gid)

    return log_file


def _parse_group(log_group):
    if os.name == 'nt':
        raise Exception('This function is not supported on windows')

    row = grp.getgrnam(log_group)
    return row.gr_gid


def _parse_user(user):
    if util.is_windows_os():
        raise Exception('This function is not supported on windows')

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
        print("Warning: user \'%s\' does not exist - "
              "duoauthproxy will not drop privileges" % user, file=sys.stderr)
    if row:
        return (row.pw_uid, row.pw_gid)
    return (None, None)
