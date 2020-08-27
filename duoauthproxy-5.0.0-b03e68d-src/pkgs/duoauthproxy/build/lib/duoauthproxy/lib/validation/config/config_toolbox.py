import re

from duoauthproxy.lib import const, ip_util, protect, secret_storage, util
from duoauthproxy.lib.validation.config import (
    config_key_tools,
    config_value_tools,
    file_tools,
    ldap_tools,
    type_tools,
)


class ConfigTestToolbox(object):
    """
    Toolbox containing tests for validating the auth proxy config. These tests
    cover config checking only and do not test connectivity.
    """

    def test_config_has_value(self, config, key, optionally_protected=False):
        """
        Tests that the provided config contains a non-empty value for the
        specified key. Does not validate the value contents or type.

        Args:
            config (ConfigDict): Config to check for the key and value
            key (str): The key whose value to validate
            optionally_protected (bool): True if the key can be suffixed with
            the '_protected' keyword.

        Returns:
            bool:  Whether the config has a usable value for the config key
        """
        if optionally_protected:
            # Should we check that both are not present?
            protected_key = key + "_protected"
            return config_key_tools.is_key_usable(
                config, key
            ) or config_key_tools.is_key_usable(config, protected_key)
        else:
            return config_key_tools.is_key_usable(config, key)

    def test_key_is_dynamic(self, config, key):
        return re.search(r"_\d+$", key) is not None

    def test_config_has_any_dynamic_key(self, config, key, optionally_protected=False):
        """
        Tests that some dynamic key exists with the given base

        Args:
            config (ConfigDict): The config containing the dynamic values to check for
            key (str): The base of the key to check against

        Returns:
            bool: Whether any dynamic key appears which matches the stem
        """
        return len(util.get_dynamic_keys(config, key, optionally_protected)) > 0

    def test_config_has_key(self, config, key, optionally_protected=False):
        """
        Tests that the provided config contains the specified key as an entry.
        Does not validate the value associated with the key.

        Args:
            config (ConfigDict): Config to check for the key
            key (str): The key to check for
            optionally_protected (bool): True if the key can be suffixed with
            the '_protected' keyword.

        Returns:
            bool: Whether the config has the key present
        """
        if optionally_protected:
            # Should we check that both are not present?
            if self.test_key_is_dynamic(config, key):
                key_parts = re.search(r"^(.*)_(\d+)$", key)
                protected_key = "{0}_protected_{1}".format(
                    key_parts.group(1), key_parts.group(2)
                )
            else:
                protected_key = key + "_protected"
            return config_key_tools.is_key_present(
                config, key
            ) or config_key_tools.is_key_present(config, protected_key)
        else:
            return config_key_tools.is_key_present(config, key)

    def test_is_int(self, config, key):
        """
        Tests that the value in the config for the provided key is an int

        Args:
            config (ConfigDict): The config containing the value to test
            key (str): The key used to look up the value to test

        Returns:
            bool: Whether the specified key holds something that can be an int
        """
        return type_tools.is_intable(config, key)

    def test_is_positive_int(self, config, key):
        """
        Tests that the value in the config for the provided key is a positive integer

        Args:
            config (ConfigDict): The config containing the value to test
            key (str): The key used to look up the value to test

        Returns:
            bool: Whether the specified key holds positive integer
        """
        return type_tools.is_intable(config, key) and int(config.get(key)) >= 0

    def test_is_string(self, config, key, allow_empty=False):
        """
        Tests that the value in the config for the provided key is a string

        Args:
            config (ConfigDict): The config containing the value to test
            key (str): The key used to look up the value to test
            allow_empty (bool): True to treat an empty string as valid

        Returns:
            bool: Whether the specified key holds something that can be a string
        """
        return type_tools.is_stringable(config, key, allow_empty)

    def test_is_bool(self, config, key):
        """
        Tests that the value in the config for the provided key is a boolean

        Args:
            config (ConfigDict): The config containing the value to test
            key (str): The key used to look up the value to test

        Returns:
            bool: Whether the specified key holds something that can be a bool
        """
        return type_tools.is_boolable(config, key)

    def test_valid_enum(self, config, key, enum, transform=lambda x: x):
        """
        Tests the the value in the config for the provided key is a valid value
        of the specified enum

        Args:
            config (ConfigDict): The config containing the value to test
            key (str): The key used to look up the value to test
            enum (list): The enum to check against
            transform (function): A function that will take the value at `key`.
                                  Function will be applied before checking inclusion in `enum`

        Returns:
            bool: Whether the specified key holds a value from the enum of possible values
        """
        value = config.get(key)
        return config_value_tools.is_value_in_defined_set(value, enum, transform)

    def test_valid_port(self, config, key):
        """
        Tests that the value in the config for the provided key is non-empty
        and is a valid port number

        Args:
            config (ConfigDict): The config containing the value to test
            key (str): The key used to look up the value to test

        Returns:
            bool: Whether the key holds a value that can be a valid port
        """
        return type_tools.is_intable(config, key) and 1 <= int(config.get(key)) <= 65535

    def test_dn(self, config, dn_key):
        """
        Tests that the value in the config for the provided dn_key is non-empty
        and is of a valid format

        Args:
            config (ConfigDict): The config containing the value to test
            dn_key (str): The key used to look up the DN value to test

        Returns:
            bool: Whether the key holds a value that's a valid DN
        """
        return ldap_tools.is_ldap_dn(config, dn_key)

    def test_ldap_filter(self, config, ldap_filter_key):
        """
        Tests that the value in the config for the provided ldap filter key
        is non-empty and of a valid format

        Args:
            config (ConfigDict): The config containing the value to test
            ldap_filter_key (str): The key used to look up the ldap
            filter to test

        Returns:
            bool: Whether the key holds a value that's a valid ldap filter
        """
        return ldap_tools.is_ldap_filter(config, ldap_filter_key)

    def test_file_readable(self, config, file_path_key):
        """
        Tests that the provided file path corresponds with an actual file
        on the filesystem

        Args:
            config (ConfigDict): The config containing the value to test
            file_path_key (str): The key used to look up the file path
            of the file to test

        Returns:
            bool: Whether the filename specified points to an existing, openable file
        """
        return file_tools.check_file(config.get(file_path_key))

    def test_is_valid_directory(self, config, dir_path_key):
        """ Check if a directory exists
        Args:
            path (str): Path starting at INSTALL-DIR/.
            If path begins with / then INSTALLDIR prefix is ignored
        Returns:
            bool: True if the dir exists; False otherwise
        """
        return file_tools.check_directory(config.get(dir_path_key))

    def test_secrets_file(self):
        """
        Test that the secrets file is available, and it seems to have the correct content

        Returns:
           (bool) Whether the secrets file seems to be in good shape
        """
        secrets_file = secret_storage.get_storage_filename()
        file_accessible = file_tools.check_file(secrets_file)

        proxy_key_found = False
        if file_accessible:
            try:
                if secret_storage.retrieve_secret(const.DRPC_PROXY_KEY_IDENTIFIER):
                    proxy_key_found = True
            except (KeyError, IOError):
                pass

        return file_accessible and proxy_key_found

    def test_items_paired(self, config, key1, key2):
        """
        Check that if key1 is present so is key2

        Args:
            config (ConfigDict): the section config to check
            key1 (str): First config key
            key2 (str): Second config key

        Returns:
            Bool: whether or not both keys are present or neither is present
        """
        return config_key_tools.is_key_present(
            config, key1
        ) and config_key_tools.is_key_present(config, key2)

    def test_is_valid_ip(self, config, ip_key):
        """
        Check the validity of an ip address in the config

        Args:
            config (ConfigDict): the section config to check
            ip_key(str): key to an ip range. Formats are single, range, cidr, and IP/netmask

        Returns:
            Bool: whether or not the ip range is well formatted
        """
        ip_range = config.get(ip_key)
        return ip_util.is_valid_ip(ip_range)

    def test_is_valid_single_ip(self, config, ip_key):
        """
        Check the validity of a single ip address in the config

        Args:
            config (ConfigDict): the section config to check
            ip_key (str): key name for the ip address to check

        Returns:
            Bool: whether or not the ip is well formatted
        """
        ip = config.get(ip_key)
        return ip_util.is_valid_single_ip(ip)

    def test_is_ikey(self, config, ikey_key):
        """
        Check the validity of an ikey in the config

        Args:
        config (ConfigDict): the section config to check
        ikey_key (str): key for the ikey to check

        Returns:
            Bool: whether or not the ikey is well formatted
        """
        try:
            ikey = config.get_str(ikey_key)
        except AssertionError:
            return False
        return re.match("^DI[A-Z0-9]{18}$", ikey) is not None

    def test_is_skey(self, config, skey_key):
        """
        Check the validity of an skey in the config

        Args:
        config (ConfigDict): the section config to check
        skey_key (str): key for the skey to check

        Returns:
            Bool: whether or not the skey is well formatted
        """
        try:
            skey = config.get_str(skey_key)
        except AssertionError:
            return False
        return re.match("^[a-zA-Z0-9]{40}$", skey) is not None

    def test_is_rikey(self, config, rikey_key):
        """
        Check the validity of an rikey in the config

        Args:
        config (ConfigDict): the section config to check
        skey_key (str): key for the skey to check

        Returns:
            Bool: whether or not the rikey is well formatted
        """
        try:
            rikey = config.get_str(rikey_key)
        except AssertionError:
            return False
        return re.match("^RI[A-Z0-9]{18}$", rikey) is not None

    def test_valid_permutation(self, config, key, enum, separator=",", repeats=False):
        """
        Check the validity of a string which should contain a list of seperated
        values which are all in a given enumerated list

        Args:
        config (ConfigDict): the section config to check
        key (str): key for the permutation string
        enum ([str]): enumerated list of values which can be in the permutation
        separator: (str): character separating items in permutation
        repeats: whether the permutation allows the same enum value to be present more than once

        Returns:
            Bool: whether or not he permutation is well formatted

        Example:
            factors=phone, push
            toolbox.test_valid_permutation(config, 'factors', ['push', 'phone', 'passcode'], ',', False)

            return true
        """

        value = config.get(key)
        return config_value_tools.is_valid_permutation(value, enum, separator, repeats)

    def test_is_codec(self, config, codec_key):
        try:
            codec = config.get_str(codec_key)
        except AssertionError:
            return False
        return config_value_tools.is_codec(codec)

    def get_unexpected_keys_present(self, config, fixed_keys, dynamic_keys):
        """
        Get a list of the unexpected keys present in a section config.

        The provided 'dynamic' list should include key prefixes the can appear with trailing numbers
          (i.e. to allow 'radius_ip_1', 'radius_ip_2', include 'radius_ip' in the dynamic list)
        The provided 'fixed' list of keys should include all other keys that can be present in the section

        Args:
            section_config (ConfigDict): the section config to check
            fixed_keys ([str]): the allowed 'fixed' keys
            dynamic_keys ([str]): the allowed 'dynamic' keys

        Returns:
            List(str): the keys present in the section that are not included in the provided fixed/dynamic lists
        """
        return config_key_tools.get_unexpected_keys(config, fixed_keys, dynamic_keys)

    def test_keys_unpaired(self, config, key_one, key_two):
        """ Test that at most 1 of the provided two keys is present
        Args:
            section_config (ConfigDict): the section config to test
            key_one (str): One key
            key_two (str): The other key
        Returns:
            bool
        """
        return config_key_tools.are_keys_unpaired(config, key_one, key_two)

    def test_ip_range(self, config, ip_range_key):
        """ Test that a value is an IP range in 1 of 4 formats
        Args:
            config (ConfigDict): the section config to test
            ip_range_key (str): Formats are single, range, cidr, and IP/netmask
        Returns:
        bool
        """
        ip = config.get(ip_range_key)
        return all(ip_util.is_valid_ip(ip) for ip in util.parse_delimited_set(ip))

    def test_is_tls_version(self, config, tls_version_key):
        """ Tests that a value is a valid TLS version
        Args:
            config (ConfigDict): the section config to test
            tls_version_key (str): key to a tls version

        Returns:
            bool
        """
        tls_version = config.get(tls_version_key)
        return config_value_tools.is_tls_version(tls_version)

    def test_is_cipher_list(self, config, cipher_list_key):
        """ Tests that a value is a valid cipher list
        Args:
            config (ConfigDict): the section config to test
            cipher_list_key (str): key to a cipher list value

        Returns:
            bool
        """
        cipher_list = config.get(cipher_list_key)
        return config_value_tools.is_cipher_list(cipher_list)

    def test_is_protect_enabled(self):
        """ Tests that encryption is possible on this machine
        Returns:
            bool
        """
        return protect.PROTECT_ENABLED

    def test_is_valid_protected_value(self, config, protected_value_key):
        """ Tests that we can actually decrypt the value provided
        Args:
            config (ConfigDict): the section config to test
            protected_value_key (str): key to a protected value
        Returns:
            bool
        """
        try:
            protect.unprotect(config[protected_value_key])
        except Exception:
            return False
        else:
            return True


STANDARD_CONFIG_TOOLBOX = ConfigTestToolbox()
