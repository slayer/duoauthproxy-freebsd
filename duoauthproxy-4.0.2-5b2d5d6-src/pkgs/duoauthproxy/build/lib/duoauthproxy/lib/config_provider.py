#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from configparser import ConfigParser, MissingSectionHeaderError
from configparser import NoSectionError, ParsingError, DuplicateOptionError
from io import StringIO
import re
import os

from collections import OrderedDict

from duoauthproxy.lib import protect, util
from .config_error import ConfigError

# Maps non-standard keys to their standard name for use during ConfigDict creation.
# This allows for there to be a one-to-many relationship between standard keys
# aliases.
STANDARD_KEY_MAP = {
    'concat_mode': 'allow_concat',
}


class ConfigProvider:
    """
    Provides access to an Auth Proxy configuration
    """
    def __init__(self, ini_string, source=None, apply_overrides=True):
        """
        Create a ConfigProvider based on the provided configuration string (in INI style).

        Run validations on the configuration:
          No duplicates allowed
          At least one section
        and raise a ConfigError if there's a problem

        Args:
            ini_string (str): An INI style string containing the configuration
            source (str): Where the INI string came from, for logging/error reporting purposes
            apply_overrides (bool): Only set false if you don't want main overrides to apply. Used by authproxy_passwd
        """
        duplicates = find_duplicate_sections(ini_string)
        if duplicates:
            raise ConfigError("Configuration loaded from {0} has duplicate sections: {1}".format(source, duplicates))

        self.parser = ConfigParser(interpolation=None)

        config_stringio = StringIO(ini_string)
        try:
            self.parser.read_file(config_stringio)
        except MissingSectionHeaderError:
            raise ConfigError('Config loaded from {0} has no sections.'.format(source))
        except ParsingError as e:
            raise ConfigError('Config is unparseable or contains bad comment: {}'.format(e))
        except DuplicateOptionError as e:
            raise ConfigError('Configuration has duplicated keys in the given section: {}'.format(e))

        if apply_overrides:
            self._apply_main_overrides()

    def list_sections(self):
        """
        Return a list of the sections present in the config

        Returns:
            A list of the section names (strings) that are in the config
        """
        return self.parser.sections()

    def get_section_client(self, section_name):
        """Return the client for a given section
        Args:
            section_name (str): Name of section
        Returns:
            str|None: the name of the client section
        """
        clients = [k for k in self.list_sections() if 'client' in k.lower()]
        ad_clients = [c for c in clients if c.startswith('ad_client')]
        main_client = self.get_main_section_config().get_str('client', '')
        if get_module_type(section_name) != 'server':
            raise ConfigError('Attempted to get the client for a non-server section')
        if section_name == 'radius_server_duo_only':
            return None

        section_config = self.get_section_config(section_name)
        client_name = section_config.get_str("client", "")
        if not client_name:
            if 'ldap_server' in section_name and len(ad_clients) == 1:
                client_name = ad_clients[0]
            elif main_client:
                client_name = main_client
            elif len(clients) == 1:
                client_name = clients[0]

        if client_name:
            return client_name.lower()
        else:
            return None

    def get_section_config(self, section_name):
        """
        Get the configuration details for a specified config section.

        Args:
            section_name (str): The section name whose config we want

        Returns:
            A base.ConfigDict for the requested section.  Will be blank if no such section exists.
        """
        if not section_name or section_name not in self.list_sections():
            return ConfigDict({})

        return ConfigDict(self.parser.items(section_name, raw=True))

    def get_main_section_config(self):
        """
        Convenience method for getting the 'main' section config, so the caller doesn't need to know
        the casing of the config

        Returns:
            The section config for the main section
        """
        main_section_name = find_main_section_name(self.list_sections())
        return self.get_section_config(main_section_name)

    def get_all_sections(self):
        """
        Convenience method to get all the section configs

        Returns:
            OrderedDict: map of section name -> ConfigDict for that section,
            includes all sections present in the config

        """
        all_sections = OrderedDict()

        for section_name in self.list_sections():
            all_sections[section_name] = self.get_section_config(section_name)

        return all_sections

    def _apply_main_overrides(self):
        """ Apply special logic to the main section.

        The main section config may contain a 'server' and 'client' key.  If so, the specified client
        should override any client declaration made in the specified server section.
        The main section can also specify flags that should be passed down into the server sections
        and that will happen here as well.
        """
        main_config = self.get_main_section_config()
        if 'server' in main_config and 'client' in main_config:
            main_server = main_config.get_str('server')
            main_client = main_config.get_str('client')
            try:
                self.parser.set(main_server, 'client', main_client)
            except NoSectionError:
                # There is no section for the specified server in [main], so ignore it
                pass

        debug = main_config.get_bool('debug', False)
        http_ca_certs_file = main_config.get_str('http_ca_certs_file', '')
        http_proxy_host = main_config.get_str('http_proxy_host', '')
        interface = main_config.get_str('interface', '')

        for section in self.list_sections():
            if debug:
                self.parser.set(section, 'debug', value='True')

            if http_ca_certs_file:
                self.parser.set(section, 'http_ca_certs_file', value=http_ca_certs_file)

            if http_proxy_host:
                http_proxy_port = main_config.get_str('http_proxy_port', '80')
                if get_module_type(section) in ['server', 'cloud']:
                    self.parser.set(section, 'http_proxy_host', value=http_proxy_host)
                    self.parser.set(section, 'http_proxy_port', value=http_proxy_port)

            if interface:
                module_type = get_module_type(section)
                if module_type == 'server' or module_type == 'http_proxy':
                    # Only apply main interface if one isn't specified already
                    if not self.parser.has_option(section, 'interface'):
                        self.parser.set(section, 'interface', value=interface)

    def _add_encrypted_value(self, section, option):
        """ Encrypt the field, turn the option to _protected. Add it to the parser"""
        if not protect.PROTECT_ENABLED:
            raise ConfigError("Attempting to encrypt on a system that doesn't support it")

        value = self.parser.get(section, option)
        encrypted_value = protect.protect(value)

        protected_option = _generate_protected_option(option)
        self.parser.set(section, protected_option, encrypted_value)

    def _remove_unencrypted_value(self, section, option):
        """ Remove the unprotected key value pair from the parser"""
        try:
            option_exists = self.parser.remove_option(section, option)
            if not option_exists:
                raise ConfigError("Failed to remove option: {0} in section: {1}".format(option, section))
        except NoSectionError:
            raise ConfigError("Section could not be found: {}".format(section))

    def encrypt_all_values(self):
        """ Use the win32 encryption on all fields that are able to be encrypted
        Key names will have _protected appended to them"""
        for section in self.list_sections():
            for option in self.parser.options(section):
                if _is_key_protectable(option):
                    self._add_encrypted_value(section, option)
                    self._remove_unencrypted_value(section, option)

    def write_ini_file(self, filepath):
        """ Turn a configuration object back into an ini file
        Args:
            filepath (str): The full path to the configuration file to write
        """
        with open(filepath, "w") as config_file:
            self.parser.write(config_file)

    @staticmethod
    def from_ini_file(config_file, source, apply_overrides=True):
        """
        Factory method for creating a ConfigProvider from a provided INI file.

        Will read the file contents, clean it up*, and return the created ConfigProvider.

        *Normalize line endings

        Args:
            config_file (file): the INI file to read
            source (str): Where the INI file came from, for logging/error reporting purposes
            apply_overrides (bool): Only set false if you don't want main overrides to apply. Used by authproxy_passwd

        Returns:
            A ConfigProvider built with the contents of the INI file
        """
        file_contents = config_file.read()
        file_contents = normalize_line_endings(file_contents)
        return ConfigProvider(file_contents, source, apply_overrides)


def get_config(config_filename=None, apply_overrides=True):
    """
    Load whatever config file the systems is set up to use by default
    Currently this only supports the loading of local .INI files but this will likely
    change in the near future

    Args:
        config_filename (str): Specific file patch to load the config file from
        apply_overrides (bool): See ConfigProvider.__init__

    Returns:
        A ConfigProvider object
    """
    return _get_local_config(config_filename, apply_overrides=apply_overrides)


def _get_local_config(config_filename=None, apply_overrides=True):
    """
    Load local config file optionally specified by 'config_filename'

    Args: See get_config
    Returns: A ConfigProvider object
    """
    try:
        if not config_filename:
            root = util.get_home_dir()
            config_filename = os.path.join(root, 'conf', 'authproxy.cfg')
        # open configfile and construct ConfigProvider
        with open(config_filename, "r") as config_file:
            configuration = ConfigProvider.from_ini_file(config_file, os.path.abspath(config_filename), apply_overrides)
    except IOError:
        raise ConfigError('Config file missing or unreadable: {0}'.format(config_filename))

    return configuration


def find_duplicate_sections(ini_string):
    """
    Find (case insensitively) any duplicate sections in the provided INI-like string

    Args:
        ini_string (str): the config ini string to check

    Returns:
        A (possibly empty) list of any duplicated sections
    """
    sections_found = set()
    duplicates = set()

    for match in map(str.lower, re.findall(r'^\[(\w+)\]', ini_string, re.MULTILINE)):
        if match in sections_found:
            duplicates.add(match)
        else:
            sections_found.add(match)

    return list(duplicates)


def find_main_section_name(section_names):
    """
    Check the list of section_names (strings) for anything that matches 'main' in any casing.

    Args:
        section_names (list of str): The seciton name list to search

    Returns:
        The 'main' section name in original casing, or None.
    """
    for name in section_names:
        if name.lower() == 'main':
            return name

    return None


def normalize_line_endings(config_string):
    """
    Transform the provided string to prevent if having both UNIX and Windows
    style line endings.  If there is a mix, replace the UNIX ones with Windows.

    Args:
        config_string (str): The string to transform

    Returns:
        The transformed string
    """
    if (re.search(r'(?<!\r)\n', config_string) is not None and
            re.search(r'\r\n', config_string) is not None):
        # The config string has both Windows-style(\r\n) and Unix-style(\n) line
        # endings. Since there are Windows-style line endings, assume this is
        # a Windows config file and replace all the Unix-style line endings
        # with their Windows equivalent
        config_string = re.sub('(?<!\r)\n', r'\r\n', config_string)
    return config_string


def get_module_type(section_name):
    """Return module type for a given section name
    Args:
        section_name (str): Name of section
    Returns:
        str: One of 'server' 'client' 'cloud' 'http_proxy' or ''
    """
    module_type = ''
    if 'server' in section_name.lower():
        module_type = 'server'
    elif 'client' in section_name.lower():
        module_type = 'client'
    elif 'cloud' in section_name.lower():
        module_type = 'cloud'
    elif 'http_proxy' in section_name.lower():
        module_type = 'http_proxy'

    return module_type


def _is_key_protectable(option):
    """ Given an option see if it is one we support encryption for.
    Note: radius_secret comes in the format radius_secret_1 radius_secret_2
    so we just check if the prefix is present
    """
    if 'protected' in option:
        # Already protected
        return False

    protectable_keys = ['service_account_password', 'secret', 'radius_secret', 'skey']
    for key in protectable_keys:
        if option.startswith(key):
            return True
    return False


def _generate_protected_option(option):
    """Given regular option that can be protected return the proected syntax"""
    rad_prefix = 'radius_secret_'
    if option.startswith(rad_prefix):
        secret_num = option[len(rad_prefix):]
        return 'radius_secret_protected_' + secret_num

    return option + '_protected'


def get_standard_key(key):
    # this may later be replaced with more logic to do things like add '_'s
    return STANDARD_KEY_MAP.get(key, key)


class ConfigDict(dict):
    def __init__(self, elements):
        super(ConfigDict, self).__init__(elements)
        self.standardize_keys()

    def standardize_keys(self):
        # using list here pull the initial list of keys into a separate array
        # because we might modify the current list of keys
        for key in list(self.keys()):
            standard_key = get_standard_key(key)
            if standard_key != key:
                value = self[key]
                del self[key]
                self[standard_key] = value

    def get_str(self, key, default=None):
        assert(default is None or isinstance(default, str))

        value = self.get(key)
        if value is None:
            if default is None:
                raise ConfigError('Missing required configuration item: \'%s\'' % key)
            else:
                return default
        else:
            assert isinstance(value, str)
            return value

    def get_protected_str(self, key, unsecured_key, default=None):
        assert(default is None or isinstance(default, str))

        if not protect.PROTECT_ENABLED:
            return self.get_str(unsecured_key, default)

        value = self.get(key)
        if value:
            assert isinstance(value, str)
            return protect.unprotect(value)
        elif unsecured_key:
            return self.get_str(unsecured_key, default)
        return default

    def get_int(self, key, default=None):
        assert(default is None or isinstance(default, int))

        value = self.get(key)
        if value is None:
            if default is None:
                raise ConfigError('Missing required configuration item: \'%s\'' % key)
            else:
                return default
        else:
            assert isinstance(value, str)
            try:
                return int(value)
            except ValueError:
                raise ConfigError('Invalid value for configuration item: \'%s\' must be an integer'
                                  % key)

    def get_bool(self, key, default=None):
        assert(default is None or isinstance(default, bool))

        value = self.get(key)
        if value is None:
            if default is None:
                raise ConfigError('Missing required configuration item: \'%s\'' % key)
            else:
                return default
        else:
            # accept (case-insensitive) 'true', 'false', zero, or nonzero. all
            # other strings will be rejected
            assert isinstance(value, str)
            if value.lower() == 'true':
                return True
            elif value.lower() == 'false':
                return False
            else:
                try:
                    return bool(int(value))
                except ValueError:
                    raise ConfigError('Invalid value for configuration item: \'%s\' must be a boolean value'
                                      % key)

    def get_enum(self, key, values, default=None, transform=lambda x: x):
        assert(default is None or default in values)

        value = self.get(key)
        if value is None:
            if default is None:
                raise ConfigError('Missing required configuration item: \'%s\'' % key)
            else:
                return default
        else:
            assert isinstance(value, str)
            value = transform(value)

            if value not in values:
                raise ConfigError('Invalid value for configuration item: \'%s\' must be one of %s'
                                  % (key, ', '.join('\'%s\'' % x for x in values)))
            return value
