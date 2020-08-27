import functools

from enum import Enum
from twisted.logger import LogLevel

from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    BaseResult
)


class ConfigResultType(Enum):
    """
    The types of results from checking a value in the auth proxy configuration.
    """

    def __new__(cls, id, value):
        """
        Args:
            id (int): ID of the enum value
            value (string):
        """
        obj = object.__new__(cls)
        obj._value_ = value
        obj.id = id
        return obj

    UnexpectedKey = (1, "An unexpected configuration item was found: {key}")
    MissingKey = (2, "A required configuration item is missing: {key}")
    # T56466: Usages of InvalidValue may be passing in a 'value' kwarg. Initially
    # the message did print a value but it was removed for security reasons.
    InvalidValue = (3, "The {key} value provided is invalid.")
    UnmetDependency = (4, "{message}")
    SkippedTest = (5, "The Auth Proxy did not run the {test} check "
                      "because of the configuration problem with {key}. "
                      "Resolve that configuration issue and rerun the tester.")
    IncompatibleKeys = (6, "The following keys should not be used at the same time: {key1}, {key2}. Please pick just one.")
    UnpairedKey = (7, "{key1} must be provided when specifying {key2}")
    KeyIncompatibleWithSection = (8, "{key1} cannot be present when section [{key2}] is specified")
    NetworkContention = (9, "Conflicting network configuration.\n{section1} listens on {interface}:{port} for clients in {ip1}.\n{section2} listens on {interface}:{port} for clients in {ip2}.\nMessages from the overlapping IP range will be sent to sections based on their order in the configuration. This is not recommended as it can cause unexpected behavior.")
    InvalidClientServerMapping = (10, "The client name '{client_name}' could "
                                      "not be mapped to a valid client "
                                      "configuration for the [{section}] section.")
    PortCollision = (11, "The following server sections have a port collision: {sections}. "
                         "They both listen on port: {port} and attempt to use the interface: '{interface}'. "
                         "Please modify the ports in your configuration to resolve this.")
    KeyInvalidWithClient = (12, "The key {key} is not valid with client {client}")
    IneffectiveConfig = (13, "{key} in section [{section}] has no effect when {condition}")
    SameSectionPortCollision = (14, "The following server section has a port collision: {section}. "
                                    "Port {port} is configured for both SSL and non-SSL connections. "
                                    "Please modify the ports in your configuration to resolve this."
                                )
    ProtectUnavailable = (15, "Usage of protected value(s): {keys} is not possible because this machine does not "
                          "support our protection library. Please make sure you are running a Windows OS "
                          "with access to the Data Protection API."
                          )
    InvalidProtectedValue = (16, "The protected value for {key} could not be decrypted and therefore cannot be "
                                 "used. This may happen if the secret was encrypted on a different machine and "
                                 "copied to this machine. Please try protecting this value again."
                             )


class ConfigResultLevel(Enum):
    """
    The possible result levels to associate with a ConfigResult
    """

    def __new__(cls, id, value, twisted_logging_level):
        """
        Args:
            id (int): ID of the enum value
            value (string): String representation of the
            twisted_logging_level (LogLevel): Twisted logging level to use
        """
        obj = object.__new__(cls)
        obj._value_ = value
        obj.id = id
        obj.twisted_logging_level = twisted_logging_level
        return obj

    Error = (1, 'error', LogLevel.error)
    Warning = (2, 'warning', LogLevel.warn)
    Info = (3, 'info', LogLevel.info)
    Debug = (4, 'debug', LogLevel.info)


class ConfigResult(BaseResult):
    """
    Result object representing the result of checking a single value in the
    auth proxy configuration.
    """

    def __init__(self, result_type, level=ConfigResultLevel.Error, **kwargs):
        """
        Args:
            result_type (ConfigResultType): The type of the config result
            level (ConfigResultLevel): The logging level of the result
            **kwargs: Any necessary keyword arguments to interpolate the string
                      associated with the provided ConfigResultType
        """
        self.result_type = result_type
        self.level = level
        self.message_kwargs = kwargs

    def is_successful(self):
        return self.level != ConfigResultLevel.Error

    def is_warning(self):
        return self.level == ConfigResultLevel.Warning

    def to_log_output(self, logger):
        logger.emit(self.level.twisted_logging_level,
                    self.result_type.value, **self.message_kwargs)

    def __eq__(self, other):
        return self.result_type == other.result_type \
            and self.level == other.level \
            and self._message_kwargs_equal(self.message_kwargs, other.message_kwargs)

    def _message_kwargs_equal(self, my_kwargs, other_kwargs):
        if set(my_kwargs.keys()) != set(other_kwargs.keys()):
            return False

        for kwarg_key, kwarg_value in my_kwargs.items():
            if isinstance(kwarg_value, list):
                # We don't care about list order
                if set(kwarg_value) != set(other_kwargs[kwarg_key]):
                    return False
            else:
                if kwarg_value != other_kwargs[kwarg_key]:
                    return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        """
        String dump of the result for debugging and inspection purposes

        Returns:
            A string dump of the result
        """
        message = "Type: {0}. Level: {1}. Message: {2}"
        return message.format(self.result_type, self.level,
                              self.result_type.value.format(**self.message_kwargs))


def result_creator(result_type, **kwargs):
    """
    Creates a partial ConfigResult with a bound ConfigResultType
    Args:
        result_type (ConfigResultType): The result type
        **kwargs: Any kwargs that should be passed along to the
            ConfigResult constructor

    """
    return functools.partial(ConfigResult, result_type=result_type, **kwargs)


# Convenience functors for creating result objects
UnexpectedKey = result_creator(ConfigResultType.UnexpectedKey)
MissingKey = result_creator(ConfigResultType.MissingKey)
InvalidValue = result_creator(ConfigResultType.InvalidValue)
UnmetDependency = result_creator(ConfigResultType.UnmetDependency)
SkippedTest = result_creator(ConfigResultType.SkippedTest, level=ConfigResultLevel.Warning)
IncompatibleKeys = result_creator(ConfigResultType.IncompatibleKeys)
UnpairedKey = result_creator(ConfigResultType.UnpairedKey)
KeyIncompatibleWithSection = result_creator(ConfigResultType.KeyIncompatibleWithSection)
NetworkContention = result_creator(ConfigResultType.NetworkContention, level=ConfigResultLevel.Warning)
InvalidClientServerMapping = result_creator(ConfigResultType.InvalidClientServerMapping)
PortCollision = result_creator(ConfigResultType.PortCollision)
KeyInvalidWithClient = result_creator(ConfigResultType.KeyInvalidWithClient)
IneffectiveConfig = result_creator(ConfigResultType.IneffectiveConfig, level=ConfigResultLevel.Warning)
SameSectionPortCollision = result_creator(ConfigResultType.SameSectionPortCollision)
ProtectUnavailable = result_creator(ConfigResultType.ProtectUnavailable)
InvalidProtectedValue = result_creator(ConfigResultType.InvalidProtectedValue)
