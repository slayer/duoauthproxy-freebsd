#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

import argparse
import os
import platform
import sys
import warnings

from twisted.application.service import Application, Service
from twisted.logger import globalLogPublisher, textFileLogObserver
from twisted.python.log import ILogObserver

from duoauthproxy import section
from duoauthproxy.lib import fips_manager, util
from duoauthproxy.lib.primary_only_manager import PrimaryOnlyManager
from duoauthproxy.lib.radius.server import parse_radius_secrets

from .lib import (
    config_error,
    config_provider,
    const,
    forward_serv,
    http,
    log,
    log_observation,
    ssl_verify,
)

warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    message=r"^twisted\.internet\.interfaces\.IStreamClientEndpointStringParser was deprecated in "
    r"Twisted 14\.0\.0: This interface has been superseded by "
    r"IStreamClientEndpointStringParserWithReactor\.$",
)


def get_version():
    import duoauthproxy

    return duoauthproxy.__version__


class LogReadyService(Service):
    """Dumb 'service' whose sole purpose is to print out our version number
    on startup"""

    def startService(self):
        version = get_version()
        log.msg(
            "Duo Security Authentication Proxy {version} - Init Complete",
            version=version,
        )
        log.ready()
        Service.startService(self)


def create_application(args=None, twistd_user=None, log_group=None):
    home_dir = util.get_home_dir()
    os.chdir(home_dir)
    is_logging_insecure = False

    # parse command-line args, if appropriate
    primary_only_time = None
    if args:
        option_parser = argparse.ArgumentParser()

        option_parser.add_argument(
            "--primary-only",
            type=int,
            nargs="?",
            help="This option disables secondary authentication for the specified number of minutes (default 60)",
            default=None,
            const=60,
        )
        option_parser.add_argument(
            "--logging-insecure",
            action="store_true",
            help="This option enables debug, and prints logs containing passwords and possibly other secrets.",
            default=False,
        )
        options = option_parser.parse_args()
        is_logging_insecure = options.logging_insecure
        primary_only_time = options.primary_only

    config_filename = os.path.join("conf", "authproxy.cfg")
    configuration = config_provider.get_config(config_filename)

    if primary_only_time is not None:
        if primary_only_time > 240:
            print(
                "Primary only mode can only be enabled for a maximum of 4 hours (240 minutes)"
            )
            sys.exit(2)
        else:
            PrimaryOnlyManager.enable_primary_only(primary_only_time)

    main_config = configuration.get_main_section_config()
    if main_config:
        log.msg("Main Configuration:")
        log.config(main_config)

    fips_mode = main_config.get_bool("fips_mode", False)
    if fips_mode:
        fips_manager.enable()

    # Set up our observers
    if is_logging_insecure:
        observers = [textFileLogObserver(sys.stdout)]
    else:
        observers = log_observation.get_observers(main_config, twistd_user, log_group)

    for observer in observers:
        globalLogPublisher.addObserver(observer)

    # Global debug mode
    if is_logging_insecure:
        debug_mode = True
    else:
        debug_mode = main_config.get_bool("debug", False)

    http.set_debug(debug_mode)
    http.set_is_logging_insecure(is_logging_insecure)

    # Create main application.
    application = Application("duoauthproxy")
    LogReadyService().setServiceParent(application)

    fips_mode = fips_manager.status()
    if fips_mode:
        log.msg(
            "FIPS mode {0} is enabled with {1}".format(
                fips_mode, fips_manager.get_openssl_version()
            )
        )
    else:
        log.msg("FIPS mode is not enabled")

    # get ca certs file
    http_ca_certs_file = main_config.get_str("http_ca_certs_file", "")
    if http_ca_certs_file:
        http_ca_certs_file = util.resolve_file_path(http_ca_certs_file)
    else:
        http_ca_certs_file = os.path.join("conf", const.DEFAULT_HTTP_CERTS_FILE)

    # read ca certs
    if not os.path.isfile(http_ca_certs_file):
        http_ca_certs_file = os.path.join("conf", http_ca_certs_file)
    with open(http_ca_certs_file, "r") as bundle_fp:
        http.set_ca_certs(ssl_verify.load_ca_bundle(bundle_fp))

    # get proxy settings
    http_proxy_host = main_config.get_str("http_proxy_host", "")
    http_proxy_port = main_config.get_int("http_proxy_port", 80)
    if http_proxy_host:
        http.set_proxy(http_proxy_host, http_proxy_port)

    sections = section.parse_sections(configuration, is_logging_insecure)
    module_factory = section.ModuleFactory(sections, application)
    modules_by_type = module_factory.make_modules()

    if not any(modules_by_type.values()):
        raise config_error.ConfigError("No integrations in config file.")

    # Setup forwarding/server pairs by port
    for port, interface in modules_by_type.get("server", []):
        server_networks = {}
        server_names = {}
        for section_name, server_module, server_config in modules_by_type["server"][
            (port, interface)
        ]:
            client_name = configuration.get_section_client(section_name)

            if not client_name:
                if server_module.Module.no_client:
                    modules_by_type["client"]["no_client"] = None
                    client_name = "no_client"
                else:
                    raise config_error.ConfigError(
                        'Neither module %s or main has "client" value' % section_name
                    )

            if section_name.startswith(
                "ldap_server_auto"
            ) and not client_name.startswith("ad_client"):
                raise config_error.ConfigError(
                    "ad_client is required by ldap_server_auto. No ad_client found in config file. "
                )

            if client_name != "radius_client" and server_config.get_str(
                "pass_through_attr_names", ""
            ):
                raise config_error.ConfigError(
                    "Can only pass through radius attributes if using a radius client"
                )
            server_instance = server_module.Module(
                server_config, modules_by_type["client"][client_name], section_name
            )
            server_instance.setServiceParent(application)

            if section_name.startswith("radius_server_"):
                server_networks[server_instance] = parse_radius_secrets(
                    server_config
                ).keys()
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
    sections = ",".join(sorted(set(configuration.list_sections())))
    user_agent = "duoauthproxy/{0} ({1}; Python{2}; {3})".format(
        get_version(), platform.platform(), platform.python_version(), sections
    )
    http.set_user_agent(user_agent)

    # Authproxy uses globalLogPublisher to emit events. Defining a no-op emitter will squelch the creation
    # of the unwatned twistd default logging mechanisms.
    def no_op_emitter(eventDict):
        pass

    application.setComponent(ILogObserver, no_op_emitter)

    return application
