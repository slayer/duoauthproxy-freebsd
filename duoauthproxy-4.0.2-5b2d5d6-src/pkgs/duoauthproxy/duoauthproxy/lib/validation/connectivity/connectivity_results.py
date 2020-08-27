#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
# pylint: disable=C0302

import abc
import copy
import socket
from ssl import SSLError

from OpenSSL import SSL


# Abstract classes
class BaseResult(object):
    @abc.abstractmethod
    def is_successful(self):
        """
        Check if the test result should be considered to have been successful

        Returns:
            bool: True if the test should be considered successful, False otherwise

        """
        raise NotImplementedError()

    @abc.abstractmethod
    def to_log_output(self, logger):
        """
        Generate log output appropriate to the result

        Args:
            logger: The logger to output to
        """
        raise NotImplementedError()

    def is_warning(self):
        """
        Indicates if this result is a warning. By default, result objects
        will only support success or failure. Any result objects that need
        to support warnings must override this method.

        Returns:
            bool: True if the result is a warning

        """
        return False


class DynamicTestResult(BaseResult):
    def to_log_output(self, logger):
        if self.is_successful() and not self.is_warning():
            self.to_success_log_output(logger)
        else:
            self.to_failure_log_output(logger)

    @abc.abstractmethod
    def to_success_log_output(self, logger):
        raise NotImplementedError()

    @abc.abstractmethod
    def to_failure_log_output(self, logger):
        raise NotImplementedError()


class IndividualTestResult(DynamicTestResult):
    EXCEPTION_MESSAGE = "Exception: {exception_string}"

    def __init__(self, success):
        """
        A test that can either succeed or fail on its own

        Args:
            success (bool): Whether the test was successful
        """
        self.success = success

    def is_successful(self):
        """
        Check if the test was successful

        Returns:
            bool: True if the test was successful, False otherwise

        """
        return self.success


class CompositeTestResult(DynamicTestResult):
    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE)


# Skipped test results
class ConfigProblemSkippedTestResult(BaseResult):
    OUTPUT_MESSAGE = "The Auth Proxy did not run the {test_name} check because of the configuration problem with {config_key}.  " \
                     "Resolve that configuration issue and rerun the tester."

    def __init__(self, test_name, config_key):
        self.test_name = test_name
        self.config_key = config_key

    def is_successful(self):
        return False

    def to_log_output(self, logger):
        logger.warn(self.OUTPUT_MESSAGE, test_name=self.test_name, config_key=self.config_key)

    def __eq__(self, other):
        return self.test_name == other.test_name and self.config_key == other.config_key

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "Skip test {0} config_key {1}".format(self.test_name, self.config_key)


class UnmetPrerequisiteSkippedTestResult(BaseResult):
    OUTPUT_MESSAGE = "The Auth Proxy did not run the {test_name} check because of the problem(s) with the {prereq} check. " \
                     "Resolve that issue and rerun the tester."

    def __init__(self, test_name, prereq):
        self.test_name = test_name
        self.prereq = prereq

    def is_successful(self):
        return False

    def to_log_output(self, logger):
        logger.warn(self.OUTPUT_MESSAGE, test_name=self.test_name, prereq=self.prereq)

    def __eq__(self, other):
        return self.test_name == other.test_name and self.prereq == other.prereq

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "Skip test {0} prereq {1}".format(self.test_name, self.prereq)


class AuthproxyUsingPortSkippedTestResult(BaseResult):
    OUTPUT_MESSAGE = "The Connectivity Tool did not run the {test_name} check because the actual Authentication Proxy is using that port. If you need this test to run stop the Auth Proxy and try again."

    def __init__(self, test_name):
        self.test_name = test_name

    def is_successful(self):
        return True

    def to_log_output(self, logger):
        logger.info(self.OUTPUT_MESSAGE, test_name=self.test_name)

    def __eq__(self, other):
        return self.test_name == other.test_name

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "Skip test {0}".format(self.test_name)


class BadProtectedSkeyResult(BaseResult):
    OUTPUT_MESSAGE = "The provided skey_protected could not be decrypted.  " \
                     "Ensure it was encrypted correctly and on this machine - not copied from a different machine."

    def is_successful(self):
        return False

    def to_log_output(self, logger):
        logger.error(self.OUTPUT_MESSAGE)


BAD_PROTECTED_SKEY_RESULT = BadProtectedSkeyResult()


class NotApplicableTestResult(BaseResult):
    def to_log_output(self, logger):
        pass

    def is_successful(self):
        return True


NOT_APPLICABLE_TEST_RESULT = NotApplicableTestResult()


class SkippedSectionResult(BaseResult):
    MESSAGE = "No testing to be done for section."

    def is_successful(self):
        return True

    def to_log_output(self, logger):
        logger.info(self.MESSAGE)


class InvalidSectionResult(SkippedSectionResult):
    MESSAGE = "Section name is invalid so no tests were run. Please correct section name and run again."

    def to_log_output(self, logger):
        logger.warn(self.MESSAGE)

    def is_successful(self):
        return False


SKIPPED_SECTION_RESULT = SkippedSectionResult()
INVALID_SECTION_RESULT = InvalidSectionResult()


# Config problem results
class MissingConfigKeyProblem(BaseResult):
    MESSAGE = "A required configuration item is missing: {config_key}"

    def __init__(self, config_key):
        """
        A configuration problem due to a missing key

        Args:
            config_key (str): the missing key
        """
        self.config_key = config_key

    def is_successful(self):
        return False

    def to_log_output(self, logger):
        logger.error(self.MESSAGE, config_key=self.config_key)

    def __eq__(self, other):
        return self.config_key == other.config_key

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "missing config key {0}".format(self.config_key)


class InvalidConfigKeyProblem(BaseResult):
    MESSAGE = "The {config_key} value provided is invalid: {value}."

    def __init__(self, config_key, provided_value):
        """
        A config problem due to an invalid value

        Args:
            config_key (str): the config key
            provided_value (str): the provided value
        """
        self.config_key = config_key
        self.provided_value = provided_value

    def is_successful(self):
        return False

    def to_log_output(self, logger):
        logger.error(self.MESSAGE, config_key=self.config_key, value=self.provided_value)

    def __eq__(self, other):
        return self.config_key == other.config_key and self.provided_value == other.provided_value

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "invalid config key {0} with value {1}".format(self.config_key, self.provided_value)


class ConfigErrorProblem(BaseResult):
    MESSAGE = "There was a configuration problem: {error_string}."

    def __init__(self, config_error):
        """
        A config problem due to a ConfigError

        Args:
            config_error (ConfigError): the ConfigError exception describing the problem
        """
        self.config_error = config_error

    def is_successful(self):
        return False

    def to_log_output(self, logger):
        logger.error(self.MESSAGE, error_string=str(self.config_error))

    def __eq__(self, other):
        return str(self.config_error) == str(other.config_error)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "config error {0}".format(str(self.config_error))


# Individual test result objects
class ListenResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy will be able to accept connections on port {port} on {interface}"
    FAILURE_MESSAGE = "The Auth Proxy will not be able to accept connections on port {port} on {interface}.  " \
                      "{port} is already in use by another application: {port_user} running with PID: {pid}."

    def __init__(self, success, port, interface, port_user=None, pid=None, exception=None):
        """
        Result of testing whether we could listen on a system port

        Args:
            success (bool): Whether the attempt to listen succeeded
            port (int): The port on which the listen was attempted
            interface (str): The interface(s) - possibly empty - on which the listen was attempted
            exception (Exception): The exception that was encountered in the attempt
        """
        super(ListenResult, self).__init__(success)
        self.port = port
        self.interface = interface
        self.exception = exception
        self.port_user = port_user
        self.pid = pid

    def _interface_string(self):
        if self.interface:
            return self.interface
        else:
            return 'all interfaces'

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE, port=self.port, interface=self._interface_string())

    def to_failure_log_output(self, logger):
        logger.error(
            self.FAILURE_MESSAGE,
            port=self.port,
            interface=self._interface_string(),
            port_user=self.port_user,
            pid=self.pid
        )

    def __eq__(self, other):
        return (self.success == other.success
                and self.port == other.port
                and self.interface == other.interface
                and self.port_user == other.port_user
                and self.pid == other.pid
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success: {0} port: {1} interface: {2} port_user: {3} pid: {4} exception {5}".format(
            self.success,
            self.port,
            self.interface,
            self.port_user,
            self.pid,
            str(self.exception))


class HttpWebProxyResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to establish a connection to the provided proxy {http_proxy_host}:{http_proxy_port}."
    FAILURE_MESSAGE = "The Auth Proxy was not able to establish a connection to the provided proxy {http_proxy_host}:{http_proxy_port}."

    def __init__(self, success, http_proxy_host, http_proxy_port, exception=None):
        """
        Result of testing whether we could connect through the provided proxy

        Args:
            success (bool): Whether the attempt to connect succeeded
            http_proxy_host (str): The proxy host that was connect through
            http_proxy_port (int): The proxy port that was connected through
            exception (Exception): The exception that was encountered in the attempt
        """
        super(HttpWebProxyResult, self).__init__(success)
        self.http_proxy_port = http_proxy_port
        self.http_proxy_host = http_proxy_host
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE, http_proxy_host=self.http_proxy_host, port=self.http_proxy_host)

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE,
                     http_proxy_host=self.http_proxy_host,
                     http_proxy_port=self.http_proxy_port)

        logger.debug(self.EXCEPTION_MESSAGE,
                     exception_string=str(self.exception))

    def __eq__(self, other):
        return (self.success == other.success
                and self.http_proxy_host == other.http_proxy_host
                and self.http_proxy_port == other.http_proxy_port
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} port {1} host {2} exception {3}".format(
            self.success,
            self.http_proxy_port,
            self.http_proxy_host,
            str(self.exception))


class ConnectResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to establish a connection to {host}:{port}."
    FAILURE_MESSAGE = "The Auth Proxy was not able to establish a connection to {host}:{port}."

    def __init__(self, success, host, port, exception=None):
        """
        Result of testing whether we could connect to an external host:port

        Args:
            success (bool): Whether the attempt to connect succeeded
            host (str): The host that was connected to
            port (int): The port that was connected to
            exception (Exception): The exception that was encountered in the attempt
        """
        super(ConnectResult, self).__init__(success)
        self.port = port
        self.host = host
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE, host=self.host, port=self.port)

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE, host=self.host, port=self.port)
        logger.debug(self.EXCEPTION_MESSAGE, exception_string=str(self.exception))

    def __eq__(self, other):
        return (self.success == other.success
                and self.host == other.host
                and self.port == other.port
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} port {1} host {2} exception {3}".format(
            self.success,
            self.port,
            self.host,
            str(self.exception))


class LdapConnectResult(ConnectResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to establish an LDAP connection to {host}:{port}."
    FAILURE_MESSAGE = "The Auth Proxy was not able to establish an LDAP connection to {host}:{port}."


class RadiusConnectResult(ConnectResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to establish a RADIUS connection to {host}:{port}."
    FAILURE_MESSAGE = "We cannot confirm that the Auth Proxy was able to establish a RADIUS connection to {host}:{port}. In the case of an actual failure this may be due to a misconfigured secret or network issues. This may also happen if the upstream RADIUS Server does not support the Status-Server message"


class ValidateApiCredentialsResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to validate the provided API credentials."
    FAILURE_MESSAGE = "The Auth Proxy was not able to validate the provided API credentials. "

    FAILURE_MESSAGE_CHECK_CREDS = "Check that the credentials provided for {api_host} and ikey {ikey} are correct."
    FAILURE_MESSAGE_CHECK_CERTS = "This appears to be because of unreadable or invalid CA certificates passed down by [main]'s " \
                                  "http_ca_certs_file configuration option preventing the Auth Proxy from reaching out to Duo. " \
                                  "Please refer to any errors above in main's check to fix this and retry."

    def __init__(self, success, host, ikey, exception=None):
        """
        Result of testing whether API credentials were valid for calling Duo's /check API

        Args:
            success (bool):  Whether the attempt to validate the credentials succeeded
            host (str): the host that was attempted
            ikey (str): The ikey that was used
            exception (Exception): The exception that was encountered in the attempt
        """
        super(ValidateApiCredentialsResult, self).__init__(success)
        self.host = host
        self.ikey = ikey
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE)

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE)
        self._log_optional_failure_help(logger)
        logger.debug(self.EXCEPTION_MESSAGE, exception_string=str(self.exception))

    def _log_optional_failure_help(self, logger):
        """An SSL.Error or non socket-based IOError caught by can_ping_duo indicates a problem with
        bad http_ca_certs passed down from main; otherwise, indicate that the problem may have been
        due to the network.
        """
        if isinstance(self.exception, (SSL.Error, SSLError)):
            logger.error(self.FAILURE_MESSAGE_CHECK_CERTS)
        elif isinstance(self.exception, IOError) and not isinstance(self.exception, socket.error):
            logger.error(self.FAILURE_MESSAGE_CHECK_CERTS)
        else:
            logger.error(self.FAILURE_MESSAGE_CHECK_CREDS, api_host=self.host, ikey=self.ikey)

    def __eq__(self, other):
        return (self.success == other.success
                and self.host == other.host
                and self.ikey == other.ikey
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} host {1} ikey {2} exception {3}".format(
            self.success,
            self.host,
            self.ikey,
            str(self.exception))


class DuoPingResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to ping Duo at {api_host} with a latency of {latency} milliseconds."
    FAILURE_MESSAGE = "The Auth Proxy was not able to ping Duo at {api_host}."

    FAILURE_MESSAGE_CHECK_NETWORK = "Please check that the api host is correct and that outgoing HTTPS connections are not blocked, possibly by a firewall."
    FAILURE_MESSAGE_CHECK_CERTS = "This appears to be because of unreadable or invalid CA certificates passed down by [main]'s " \
                                  "http_ca_certs_file configuration option preventing the Auth Proxy from reaching out to Duo. " \
                                  "Please refer to any errors above in main's check to fix this and retry."

    def __init__(self, success, api_host, latency=0, exception=None):
        """
        Result of testing whether the Duo /ping API could be reached

        Args:
            success (bool): Whether the ping attempt was successful
            api_host (str): The host that was pinged
            latency (int): The number of milliseconds the ping call took
            exception (Exception): The exception that was encountered in the attempt
        """
        super(DuoPingResult, self).__init__(success)
        self.api_host = api_host
        self.latency = latency
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE, api_host=self.api_host, latency=self.latency)

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE, api_host=self.api_host)
        self._log_optional_failure_help(logger)
        logger.debug(self.EXCEPTION_MESSAGE, exception_string=str(self.exception))

    def _log_optional_failure_help(self, logger):
        """An SSL.Error or non socket-based IOError caught by can_ping_duo indicates a problem with
        bad http_ca_certs passed down from main; otherwise, indicate that the problem may have been
        due to the network.
        """
        if isinstance(self.exception, (SSL.Error, SSLError)):
            logger.error(self.FAILURE_MESSAGE_CHECK_CERTS)
        elif isinstance(self.exception, IOError) and not isinstance(self.exception, socket.error):
            logger.error(self.FAILURE_MESSAGE_CHECK_CERTS)
        else:
            logger.error(self.FAILURE_MESSAGE_CHECK_NETWORK)

    def __eq__(self, other):
        return (self.success == other.success
                and self.api_host == other.api_host
                and self.latency == other.latency
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} api_host {1} exception {2} latency {3}".format(
            self.success,
            self.api_host,
            self.latency,
            str(self.exception))


class TimeDriftResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The time drift between the Auth Proxy host and Duo is within acceptable limits."
    HIGH_DRIFT_MESSAGE = "The time drift between the Auth Proxy host and Duo is excessively high, at {drift} seconds.  " \
                         "This could interfere with user authorizations.  " \
                         "Ensure the Auth Proxy host's time is correct, for instance by enabling NTP."
    FAILED_CONNECT_MESSAGE = "The Auth Proxy host could not contact Duo to check the time drift between it and Duo's servers."

    def __init__(self, success, drift, exception=None):
        """
        Result of determining the time drift between Duo's server and a local server

        Args:
            success (bool): Whether the drift is within an acceptable threshold
            drift (int): Number of seconds by which Duo and the local server differ about the time
        """
        super(TimeDriftResult, self).__init__(success)
        self.drift = drift
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE)

    def to_failure_log_output(self, logger):
        if self.exception:
            logger.error(self.FAILED_CONNECT_MESSAGE)
            logger.debug(self.EXCEPTION_MESSAGE, exception_string=str(self.exception))
        else:
            logger.error(self.HIGH_DRIFT_MESSAGE, drift=self.drift)

    def __eq__(self, other):
        return (self.success == other.success
                and self.drift == other.drift
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} drift {1} exception {2}".format(
            self.success,
            self.drift,
            self.exception
        )


class SslFileResult(IndividualTestResult):
    """
    Abstract base class for specific kinds of SSL files
    """
    def __init__(self, success, file_path, exception=None):
        """
        Result of checking if a file has valid SSL content (certificates or keys)

        Args:
            success (bool):  Whether the SSL content in the file could be validated
            file_path (str): The path to the file tested
            exception (Exception):  any exception encountered while trying to validate the SSL content
        """
        super(SslFileResult, self).__init__(success)
        self.file_path = file_path
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE, file_path=self.file_path)

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE, file_path=self.file_path)
        logger.debug(self.EXCEPTION_MESSAGE, exception_string=str(self.exception))

    def __eq__(self, other):
        return (self.success == other.success
                and self.file_path == other.file_path
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} file_path {1} exception {2}".format(
            self.success,
            self.file_path,
            str(self.exception))


class SslKeyFileResult(SslFileResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to validate the SSL private key at {file_path}."
    FAILURE_MESSAGE = "The Auth Proxy was not able to validate the SSL private key at {file_path}.  " \
                      "Ensure that it is a readable, valid SSL key file using a tool like 'openssl rsa'."


class SslCertFileResult(SslFileResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to validate the SSL certificate data at {file_path}."
    FAILURE_MESSAGE = "The Auth Proxy was not able to validate the SSL certificate at {file_path}. " \
                      "Ensure that it is the correct and valid SSL certificate file using commands like 'openssl x509' and 'openssl verify', or a utility like the MMC Snap-in or Duo's 'acert.exe'. " \
                      "If your server cert was signed by a CA, ensure that the entire certificate chain (including the root/CA cert and any intermediate certs in between) is present, with your server cert at the top of the PEM file."


class SslContextResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to successfully create an SSL context for securing server connections."
    FAILURE_MESSAGE = "The Auth Proxy was not able to create an SSL context with the given certificate and private key. "
    FAILURE_MESSAGE_MISMATCHED = "This is because the private key doesn't appear to match the provided certificate. " \
                                 "Check that your private key and certificate match each other using an 'openssl modulus check', " \
                                 "and if you have a cert chain, use a tool like 'openssl verify' or Duo's 'acert.exe' to check that the cert at the top of your PEM file is your server cert and not a root or intermediate cert."
    FAILURE_MESSAGE_BAD_CIPHERS = "This is because the specified cipher list {cipher_list} is invalid. " \
                                  "Please ensure all your ciphers are spelled correctly and are properly delimited with colons."
    FAILURE_MESSAGE_BAD_TLS = "This is because the specified minimum_tls_version { } is invalid. " \
                              "Please ensure that it is either 'tls1.2', 'tls1.1', 'tls1.0' or 'ssl3'."

    def __init__(self, success, cipher_list, minimum_tls_version, exception=None):
        """
        Result of checking SSL context creation.

        Args:
            success (bool): Whether a valid SSL context could be created with the user's SSL files
            cipher_list (str): a cipher list
            minimum_tls_version (str): a minimum tls version for the server
            exception (Exception): Any exception raised by the SSL checking
        """
        super(SslContextResult, self).__init__(success)
        self.cipher_list = cipher_list
        self.minimum_tls_version = minimum_tls_version
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE)

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE)
        self._log_optional_failure_help(logger)
        logger.debug(self.EXCEPTION_MESSAGE, exception_string=str(self.exception))

    def _log_optional_failure_help(self, logger):
        if self.exception.message == 'No usable ciphers specified in cipher_list':
            logger.error(self.FAILURE_MESSAGE_BAD_CIPHERS, cipher_list=self.cipher_list)
            return

        if self.exception.message == 'incorrect minimum_tls_version':
            logger.error(self.FAILURE_MESSAGE_BAD_TLS)
            return

        err_msg = self.exception.message[0][1]
        if (err_msg == 'SSL_CTX_check_private_key' or err_msg == 'X509_check_private_key'):
            logger.error(self.FAILURE_MESSAGE_MISMATCHED)

    def __eq__(self, other):
        return (self.success == other.success
                and self.cipher_list == other.cipher_list
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} cipher list {1} exception {2}".format(
            self.success,
            self.cipher_list,
            str(self.exception))


class LdapBindResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to bind as {bind_username}."
    FAILURE_MESSAGE = "The Auth Proxy was unable to bind as {bind_username}."

    FAILURE_MESSAGE_CREDS = "Please ensure that the provided service account credentials are correct."
    FAILURE_MESSAGE_CERTS = "Please ensure that the provided SSL CA certs file matches what was exported from your domain controller. " \
                            "Check that it is also well-formed and valid by using commands like 'openssl x509' and 'openssl verify', " \
                            "or a utility like the MMC Snap-in or Duo's 'acert.exe'."

    def __init__(self, success, bind_username, exception=None):
        """
        Result of checking whether we can bind to a remote LDAP server

        Args:
            success (bool): Whether the bind attempt succeeded
            bind_username (str): The username used to bind
            exception (Exception): any exception encountered while trying to bind
        """
        super(LdapBindResult, self).__init__(success)
        self.bind_username = bind_username
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE, bind_username=self.bind_username)

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE, bind_username=self.bind_username)
        self._log_optional_failure_help(logger)
        logger.debug(self.EXCEPTION_MESSAGE, exception_string=str(self.exception))

    def _log_optional_failure_help(self, logger):
        if isinstance(self.exception, SSL.Error):
            logger.error(self.FAILURE_MESSAGE_CERTS)
        else:
            logger.error(self.FAILURE_MESSAGE_CREDS)

    def __eq__(self, other):
        return (self.success == other.success
                and self.bind_username == other.bind_username
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} bind username {1} exception {2}".format(
            self.success,
            self.bind_username,
            str(self.exception))


class LdapSearchResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy got results searching with its basic user filter.  " \
                      "It will likely be able to find specific users during authentication."
    NO_RESULTS_MESSAGE = "The Auth Proxy did not get results searching for users in DN {search_dn} using the filter {filter}.  " \
                         "It is likely that Duo would not be able to find specific users during authentication.  " \
                         "Please confirm that {search_dn} is the correct, fully qualified DN and that users should pass the filter."
    FAILED_SEARCH_MESSAGE = "The Auth Proxy got an error searching the LDAP DN {search_dn}."

    def __init__(self, success, search_dn, filter_object, exception=None):
        """
        Result of checking whether an LDAP filter returns any results

        Args:
            success (bool): Whether the search returned at least one result
            search_dn (str): The DN under which the search ran
            filter_object: The ldaptor filter object that defines the search criteria
            exception (Exception): Any exception that was encountered by the search
        """
        super(LdapSearchResult, self).__init__(success)
        self.search_dn = search_dn
        self.filter_object = filter_object
        self.exception = exception

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE)

    def to_failure_log_output(self, logger):
        if self.exception:
            logger.error(self.FAILED_SEARCH_MESSAGE, search_dn=self.search_dn)
            logger.debug(self.EXCEPTION_MESSAGE, exception_string=str(self.exception))
        else:
            logger.error(self.NO_RESULTS_MESSAGE, search_dn=self.search_dn, filter=self.filter_object.asText())

    def get_exception(self):
        return self.exception

    def __eq__(self, other):
        return (self.success == other.success
                and self.search_dn == other.search_dn
                and self.filter_object == other.filter_object
                and self.exception == other.exception)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} search dn {1} filter {2} exception {3}".format(
            self.success,
            self.search_dn,
            str(self.filter_object),
            str(self.exception)
        )


class LdapFilterParseResult(IndividualTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to parse the LDAP filter {filter_text}."
    FAILURE_MESSAGE = "The Auth Proxy was not able to parse the LDAP filter {filter_text}.  " \
                      "Please make sure it is a valid filter."

    def __init__(self, success, filter_text):
        """
        Result of testing whether an LDAP filter string could be parsed

        Args:
            success (bool): Whether the filter could be parsed
            filter_text (str): The filter text that was parsed
        """
        super(LdapFilterParseResult, self).__init__(success)
        self.filter_text = filter_text

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE, filter_text=self.filter_text)

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE, filter_text=self.filter_text)

    def __eq__(self, other):
        return (self.success == other.success
                and self.filter_text == other.filter_text)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "success {0} filter {1}".format(
            self.success,
            self.filter_text)


# Composite result objects
class LdapHostResult(CompositeTestResult):
    SUCCESS_MESSAGE = "The LDAP host {transport} connection to {host}:{port} has no connectivity problems."
    FAILURE_MESSAGE = "The LDAP host {transport} connection to {host}:{port} has connectivity problems."

    def __init__(self, hostname, port, transport_type, tcp_connect_result, ldap_connect_result, bind_result, search_result):
        """
        Composed of the results of various checks done against an LDAP host

        Args:
            hostname (str): the hostname
            port (int): the port
            transport_type (str): transport type used to connect to LDAP host (one of 'clear', 'ldaps', or 'starttls')
            tcp_connect_result (ConnectResult): the result of checking the tcp connection to the host
            ldap_connect_result (LdapConnectResult): the result of creating an LDAP client connection to the host
            bind_result (LdapBindResult): the result of checking a bind against the host
            search_result (LdapSearchResult): the result of checking a search against the host
        """
        self.hostname = hostname
        self.port = port
        self.transport_type = transport_type
        self.tcp_connect_result = tcp_connect_result
        self.ldap_connect_result = ldap_connect_result
        self.bind_result = bind_result
        self.search_result = search_result

    def is_successful(self):
        return (self.tcp_connect_result.is_successful()
                and self.ldap_connect_result.is_successful()
                and self.bind_result.is_successful()
                and self.search_result.is_successful())

    def to_success_log_output(self, logger):
        logger.info(self.SUCCESS_MESSAGE, host=self.hostname, port=self.port, transport=self.transport_type)

    def to_failure_log_output(self, logger):
        logger.warn(self.FAILURE_MESSAGE, host=self.hostname, port=self.port, transport=self.transport_type)
        self.tcp_connect_result.to_log_output(logger)
        self.ldap_connect_result.to_log_output(logger)
        self.bind_result.to_log_output(logger)
        self.search_result.to_log_output(logger)

    def __eq__(self, other):
        return (self.hostname == other.hostname
                and self.port == other.port
                and self.transport_type == other.transport_type
                and self.tcp_connect_result == other.tcp_connect_result
                and self.ldap_connect_result == other.ldap_connect_result
                and self.bind_result == other.bind_result
                and self.search_result == other.search_result)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "hostname {0} port {1} transport type {2} tcp connect {3} ldap connect {4} bind {5} search {6}".format(
            self.hostname,
            self.port,
            self.transport_type,
            str(self.tcp_connect_result),
            str(self.ldap_connect_result),
            str(self.bind_result),
            str(self.search_result)
        )


class SslResult(CompositeTestResult):
    SUCCESS_MESSAGE = "The Auth Proxy was able to create an SSL context with the given certificate and private key. " \
                      "It will most likely be able to use these credentials to create and maintain SSL-based connections such as LDAPS."
    FAILURE_MESSAGE = "The Auth Proxy was not able to create an SSL context with the given certificate and private key. " \
                      "It will be unable to use these credentials to create and maintain SSL-based connections such as LDAPS."

    def __init__(self, key_result, certificate_result, context_result):
        """
        The results of checking SSL content, including key and certificate files, and creating an SSL context
        for those keys, certs, and cipher list

        Args:
            key_result (SslKeyFileResult): The result of checking the key file
            certificate_result (SslCertFileResult): The result of checking the certificate file
            context_result (SslContextResult or UnmetPrerequisiteSkippedTestResult): The result of checking
                if an SSL context could be created with the key and cert
        """
        super(SslResult, self).__init__()
        self.key_result = key_result
        self.certificate_result = certificate_result
        self.context_result = context_result

    def is_successful(self):
        # Don't need to check key/cert result since it's implied they succeeded if context_result did too
        return self.context_result.is_successful()

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE)
        self.key_result.to_log_output(logger)
        self.certificate_result.to_log_output(logger)
        self.context_result.to_log_output(logger)

    def __eq__(self, other):
        return (self.key_result == other.key_result
                and self.certificate_result == other.certificate_result
                and self.context_result == other.context_result)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "\nkey result {0} cert result {1} context result {2}".format(
            str(self.key_result),
            str(self.certificate_result),
            str(self.context_result),
        )


class ConfigCheckResult(CompositeTestResult):
    SUCCESS_MESSAGE = "There are no configuration problems"
    FAILURE_MESSAGE = "There are configuration problems that need to be resolved."

    def __init__(self, problems):
        """
        Composed of a list of problems with the configuration

        Args:
            problems (List): List of ConfigProblems with the configuration
        """
        self.problems = problems

    def is_successful(self):
        """
        Determine if a configuration is good (i.e. there are no problems)

        Returns:
            bool: True if there are no problems, False otherwise
        """
        return all([problem.is_successful() for problem in self.problems])

    def is_warning(self):
        """
        Determine if this result is a warning.

        Returns:
            bool: True if any problem is a warning, False otherwise
        """
        return any([problem.is_warning() for problem in self.problems])

    def to_failure_log_output(self, logger):
        logger.warn(self.FAILURE_MESSAGE)
        for problem in self.problems:
            problem.to_log_output(logger)

    def __eq__(self, other):
        my_problems = copy.deepcopy(self.problems)
        their_problems = copy.deepcopy(other.problems)
        if len(my_problems) != len(their_problems):
            return False
        for item in my_problems:
            if item not in their_problems:
                return False
            else:
                their_problems.remove(item)
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "\n problems {0}".format(str([str(problem) for problem in self.problems]))


class RadiusClientResult(CompositeTestResult):
    SUCCESS_MESSAGE = "The RADIUS Client section has no connectivity issues"
    FAILURE_MESSAGE = "The RADIUS Client section has connectivity problems"

    def __init__(self, radius_connect_results):
        """
        Composed of the various results for tests run while checking a radius_client section

        Args:
            config_result (ConfigCheckResult): The result of checking the section config
            radius_connect_results (List): list of RadiusConnectResults for the defined hosts
        """
        self.radius_connect_results = radius_connect_results

    def is_successful(self):
        hosts_good = all([host.is_successful() for host in self.radius_connect_results])
        return hosts_good

    def to_failure_log_output(self, logger):
        logger.warn(self.FAILURE_MESSAGE)
        for connect_result in self.radius_connect_results:
            connect_result.to_log_output(logger)

    def __eq__(self, other):
        return self.radius_connect_results == other.radius_connect_results

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """

        connect_results_as_strings = [str(res) for res in self.radius_connect_results]
        return "\n connect: {0}".format(connect_results_as_strings)


class RadiusServerResult(CompositeTestResult):
    SUCCESS_MESSAGE = "The RADIUS Server has no connectivity problems."
    FAILURE_MESSAGE = "The RADIUS Server has connectivity problems."

    def __init__(self, config_result, ping_result, time_drift_result, validate_result, listen_result):
        """
        Composed of the various results for tests run while checking a radius_server section

        Args:
            config_result (ConfigCheckResult): The result of checking the section config
            ping_result (DuoPingResult): The result of testing if the application can /ping Duo
            time_drift_result (TimeDriftResult): The result of the time drift between Duo Cloud and the machine running the Auth Proxy
            validate_result (ValidateApiCredentialsResult): The result of testing if the application can /check Duo
                with provided API credentials
            listen_result (ListenResult): The result of testing if the application can listen
        """
        self.config_result = config_result
        self.ping_result = ping_result
        self.time_drift_result = time_drift_result
        self.validate_result = validate_result
        self.listen_result = listen_result

    def is_successful(self):
        return (self.config_result.is_successful()
                and self.ping_result.is_successful()
                and self.time_drift_result.is_successful()
                and self.validate_result.is_successful()
                and self.listen_result.is_successful())

    def to_failure_log_output(self, logger):
        logger.warn(self.FAILURE_MESSAGE)
        self.config_result.to_log_output(logger)
        self.ping_result.to_log_output(logger)
        self.time_drift_result.to_log_output(logger)
        self.validate_result.to_log_output(logger)
        self.listen_result.to_log_output(logger)

    def __eq__(self, other):
        return (self.config_result == other.config_result
                and self.ping_result == other.ping_result
                and self.time_drift_result == other.time_drift_result
                and self.validate_result == other.validate_result
                and self.listen_result == other.listen_result)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "\n config: {0}\n ping: {1}\n validate: {2}\n listen: {3}\n".format(
            str(self.config_result),
            str(self.ping_result),
            str(self.validate_result),
            str(self.listen_result))


class CloudResult(CompositeTestResult):
    SUCCESS_MESSAGE = "The Cloud connection has no connectivity problems."
    FAILURE_MESSAGE = "The Cloud connection has connectivity problems."

    def __init__(self, ping_result, time_drift_result):
        """
        Object containing the various results for checking the cloud section
        connectivity

        Args:
            ping_result (DuoPingResult): The result of testing if the
                application can /ping Duo
            time_drift_result (TimeDriftResult): The result of the time drift
                between Duo Cloud and the machine running the Auth Proxy
        """
        self.ping_result = ping_result
        self.time_drift_result = time_drift_result

    def is_successful(self):
        return (self.ping_result.is_successful() and
                self.time_drift_result.is_successful())

    def to_failure_log_output(self, logger):
        logger.warn(self.FAILURE_MESSAGE)
        self.ping_result.to_log_output(logger)
        self.time_drift_result.to_log_output(logger)

    def __eq__(self, other):
        return (self.ping_result == other.ping_result and
                self.time_drift_result == other.time_drift_result)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "\n ping: {}\n".format(str(self.ping_result))


class AdClientConnectivityResult(CompositeTestResult):
    SUCCESS_MESSAGE = "The LDAP Client section has no connectivity issues."
    FAILURE_MESSAGE = "The LDAP Client section has connectivity problems."

    def __init__(self, ldap_host_results):
        """
        Composed of the various results for tests run while checking an ad_client section

        Args:
            ldap_host_results ([LdapHostResult]): The results of checking the ldap hosts
        """
        self.ldap_host_results = ldap_host_results

    def to_failure_log_output(self, logger):
        logger.warn(self.FAILURE_MESSAGE)
        for host_result in self.ldap_host_results:
            host_result.to_log_output(logger)

    def is_successful(self):
        hosts_good = all([host_result.is_successful() for host_result in self.ldap_host_results])

        return hosts_good

    def __eq__(self, other):
        return (self.ldap_host_results == other.ldap_host_results)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "\n ldap hosts: {0}".format(
            str([str(host_result) for host_result in self.ldap_host_results])
        )


class LdapServerResult(CompositeTestResult):
    SUCCESS_MESSAGE = "The LDAP Server has no connectivity problems."
    FAILURE_MESSAGE = "The LDAP Server has connectivity problems."

    def __init__(self, ping_result, time_drift_result, validate_result, ssl_result, listen_result):
        """
        Composed of the various results for tests run which checking an ldap_server_auto section

        Args:
            ping_result (DuoPingResult): The result of testing if the application can /ping Duo
            time_drift_result (TimeDriftResult): The result of testing the time drift between the Duo cloud and the machine running the AP
            validate_result (ValidateApiCredentialsResult): The result of testing if the application can /check Duo
                with provided API credentials
            ssl_result (SslResult): The result of checking the SSL keys and certificates
            listen_result (ListenResult): The result of testing if the application can listen
        """
        self.ping_result = ping_result
        self.time_drift_result = time_drift_result
        self.validate_result = validate_result
        self.ssl_result = ssl_result
        self.listen_result = listen_result

    def is_successful(self):
        return (self.ping_result.is_successful()
                and self.time_drift_result.is_successful()
                and self.validate_result.is_successful()
                and self.ssl_result.is_successful()
                and self.listen_result.is_successful())

    def to_failure_log_output(self, logger):
        logger.warn(self.FAILURE_MESSAGE)
        self.ping_result.to_log_output(logger)
        self.time_drift_result.to_log_output(logger)
        self.validate_result.to_log_output(logger)
        self.ssl_result.to_log_output(logger)
        self.listen_result.to_log_output(logger)

    def __eq__(self, other):
        return (self.ping_result == other.ping_result
                and self.time_drift_result == other.time_drift_result
                and self.validate_result == other.validate_result
                and self.ssl_result == other.ssl_result
                and self.listen_result == other.listen_result)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "\n ping: {0}\n validate: {1}\n ssl: {2}\n listen: {3}".format(
            str(self.ping_result),
            str(self.validate_result),
            str(self.ssl_result),
            str(self.listen_result)
        )


class HttpProxyResult(CompositeTestResult):
    SUCCESS_MESSAGE = "There are no connectivity problems with the HTTP Proxy section."
    FAILURE_MESSAGE = "There are connectivity problems with the HTTP Proxy section."

    def __init__(self, config_result, listen_result, ping_result, time_drift_result):
        """
        Composed of the various results for tests run while checking an http_proxy section

        Args:
            config_result (ConfigCheckResult): The result of checking the section config
            listen_result (ListenResult): The result of testing if the application can listen
            ping_result (DuoPingResult): The result of testing if the application can /ping Duo
            time_drift_result (TimeDriftResult): The result of the time drift between the Duo cloud and the machine running the auth proxy
        """
        self.config_result = config_result
        self.listen_result = listen_result
        self.ping_result = ping_result
        self.time_drift_result = time_drift_result

    def is_successful(self):
        return (self.config_result.is_successful()
                and self.listen_result.is_successful()
                and self.ping_result.is_successful()
                and self.time_drift_result.is_successful())

    def to_failure_log_output(self, logger):
        logger.warn(self.FAILURE_MESSAGE)
        self.config_result.to_log_output(logger)
        self.listen_result.to_log_output(logger)
        self.ping_result.to_log_output(logger)
        self.time_drift_result.to_log_output(logger)

    def __eq__(self, other):
        return (self.config_result == other.config_result
                and self.listen_result == other.listen_result
                and self.ping_result == other.ping_result
                and self.time_drift_result == other.time_drift_result)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "\n config: {0}\n listen: {1}\n ping: {2} time drift: {3}".format(
            str(self.config_result),
            str(self.listen_result),
            str(self.ping_result),
            str(self.time_drift_result),
        )


class MainSectionResult(CompositeTestResult):
    SUCCESS_MESSAGE = "There are no connectivity problems with the section."
    FAILURE_MESSAGE = "There are connectivity problems with the section."

    def __init__(self, certs_result, http_proxy_result):
        """
        Composed of the various results for tests run while checking a main section

        Args:
            certs_result (SslCertFileResult): The result of checking an SSL certificate file
            http_proxy_result (HttpWebProxyResult): The result of checking if the auth proxy can connect through a http proxy
        """
        self.certs_result = certs_result
        self.http_proxy_result = http_proxy_result

    def is_successful(self):
        return self.certs_result.is_successful() and self.http_proxy_result.is_successful()

    def to_failure_log_output(self, logger):
        logger.error(self.FAILURE_MESSAGE)
        self.certs_result.to_log_output(logger)
        self.http_proxy_result.to_log_output(logger)

    def __eq__(self, other):
        return (self.certs_result == other.certs_result
                and self.http_proxy_result == other.http_proxy_result)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        return "\n certs: {0} \n http_proxy: {1}".format(str(self.certs_result), str(self.http_proxy_result))
