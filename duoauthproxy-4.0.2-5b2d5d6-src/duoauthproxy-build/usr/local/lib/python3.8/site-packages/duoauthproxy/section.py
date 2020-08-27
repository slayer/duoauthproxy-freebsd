import string
import types

from duoauthproxy import modules
from duoauthproxy.lib import secret_storage
from duoauthproxy.modules.drpc_plugins import ldap_base
from duoauthproxy.modules import drpc_plugins
from .lib import (
    base,
    config_error,
    const,
)


def parse_sections(config, is_logging_insecure):
    """ Turn a config into section object

    Args:
        config (ConfigDict): A representation of a configuration
        is_logging_insecure (bool): Whether or not logging is insecure for this configuration

    Returns:
        A list of sections
    """
    sections = []
    for section_name_raw in config.list_sections():
        if section_name_raw.lower() == 'main':
            continue
        section_config = config.get_section_config(section_name_raw)

        # Insecure logging flag cannot be set in configuration so we must set it manually
        if is_logging_insecure:
            section_config['is_logging_insecure'] = 'True'
            section_config['debug'] = 'True'

        sections.append(Section(section_name_raw, section_config))

    return sections


class Section(object):
    def __init__(self, name, config):
        self._raw_name = name
        self.config = config
        self.validate()

    @property
    def name(self):
        return self._raw_name.lower()

    @property
    def type(self):
        return self.name.rstrip(string.digits)

    @property
    def module(self):
        try:
            return getattr(modules, self.type)
        except AttributeError:
            return None

    @property
    def module_type(self):
        module_types = {
            base.ServerModule: 'server',
            base.ClientModule: 'client',
            modules.http_proxy.Module: 'http_proxy',
            # do we need this?
            # drpc_server_module.DrpcServerModule: 'drpcserver'
        }

        if self.type in ['cloud', 'sso']:
            return self.type

        if self.module:
            for t in module_types:
                if issubclass(self.module.Module, t):
                    return module_types[t]
        return 'unknown'

    def validate(self):
        try:
            if not isinstance(self.module, types.ModuleType) or self.module_type == 'other':
                raise Exception()
        except (Exception, AttributeError):
            raise config_error.ConfigError('Invalid module: \'%s\'' % self.name)


def _partition_sections(sections):
    """ Group sections by module type

    Args:
       sections ([Section]): A list of sections to group

    Returns:
        Returns a dictionary with module types as keys and sections as values
    """
    sections_by_type = {}
    for section in sections:
        sections_by_type.setdefault(section.module_type, []).append(section)

    return sections_by_type


def _make_module(application, section):
    module = section.module.Module(section.config)
    module.setServiceParent(application)
    return module


def _make_modules(application, sections):
    new_modules = {}
    for section in sections:
        new_modules[section.name] = _make_module(application, section)

    return new_modules


class ModuleFactory(object):
    def __init__(self, sections, application):
        self.sections = _partition_sections(sections)
        self.application = application
        self.module_factories = {
            'server': ServerModuleFactory(self.sections.get('server', [])),
            'client': SingleModuleFactory(self.sections.get('client', [])),
            'http_proxy': SingleModuleFactory(self.sections.get('http_proxy', [])),
            'cloud': CloudModuleFactory(self.sections.get('cloud', [])),
            'sso': SSOModuleFactory(self.sections.get('sso', [])),
            # do we need this?
            # 'drpcserver': self._make_drpc_server_modules,
        }

    def make_modules(self):
        new_modules = {}
        for t in self.module_factories:
            new_modules.setdefault(t, {})

        for t in self.sections:
            if t not in self.module_factories:
                raise config_error.ConfigError('could not find factory method for module type {0}'.format(t))

            if t == 'server':
                continue

            new_modules[t] = self.module_factories[t].make_modules(self.application)

        new_modules['server'] = self.module_factories['server'].make_modules(self.application, new_modules.get('client', []))

        return new_modules

    # do we need this?
    # def _make_drpc_server_modules(self, sections):
    #     pass


class SingleModuleFactory(object):
    def __init__(self, sections):
        self.sections = sections

    def make_modules(self, application):
        return _make_modules(application, self.sections)


class ServerModuleFactory(object):
    def __init__(self, server_sections):
        self.server_sections = server_sections

    def make_modules(self, application, client_modules):
        servers = {}
        for section in self.server_sections:
            port = section.config.get_int("port", 1812)
            interface = section.config.get_str('interface', '')
            servers.setdefault((port, interface), []).append((section.name,
                                                              section.module,
                                                              section.config))

        return servers


class CloudModuleFactory(object):
    def __init__(self, sections):
        if len(sections) > 1:
            raise config_error.ConfigError("Configuring multiple [cloud] sections isn't supported.")
        self.sections = sections

    def make_modules(self, application):
        section = self.sections[0]
        module = _make_module(application, section)

        ldap_plugin = drpc_plugins.ldap_directory_sync.LdapSyncDrpcPlugin(section.config)
        module.register_drpc_call_provider('sync_plugin', ldap_plugin)

        return [module]


class SSOModuleFactory(object):
    def __init__(self, sections):
        self.sections = sections

    def credentials_from_sections(self):
        """ Provides a data structure for getting at LDAP secrets and updates the config to contain the DRPC secrets
            Returns:
                (Dict): 'rikey'-> ServiceAccountCredential
            Side effects:
                Each ConfigDict in self.sections gets the all the shared DRPC secrets attached to it
        """
        creds = {}
        for section in self.sections:
            self._add_cloudsso_secrets_to_config(section.config)
            # Default the credentials to empty strings if they're not found since
            # they're optional depending on the configured auth_type
            creds[section.config.get_str('rikey')] = ldap_base.ServiceAccountCredential(
                username=section.config.get_str('service_account_username', ''),
                password=section.config.get_protected_str('service_account_password_protected', 'service_account_password', ''),
            )

        return creds

    def make_modules(self, application):
        creds = self.credentials_from_sections()
        section = self.sections[0]
        module = _make_module(application, section)
        ldap_plugin = drpc_plugins.ldap_sso.LdapSsoDrpcPlugin(section.config, creds)
        module.register_drpc_call_provider('sso_plugin', ldap_plugin)

        return [module]

    def _add_cloudsso_secrets_to_config(self, section_config):
        """ Put all the secrets needed to work with CloudSSO inside the provided section config """
        section_config.update({
            const.DRPC_PROXY_KEY_IDENTIFIER: secret_storage.retrieve_secret(const.DRPC_PROXY_KEY_IDENTIFIER),
            const.DRPC_API_HOST_IDENTIFIER: secret_storage.retrieve_secret(const.DRPC_API_HOST_IDENTIFIER),
            const.DRPC_SIGNING_SKEY_IDENTIFIER: secret_storage.retrieve_secret(const.DRPC_SIGNING_SKEY_IDENTIFIER),
            const.DRPC_ENCRYPTION_SKEY_IDENTIFIER: secret_storage.retrieve_secret(const.DRPC_ENCRYPTION_SKEY_IDENTIFIER),
        })
