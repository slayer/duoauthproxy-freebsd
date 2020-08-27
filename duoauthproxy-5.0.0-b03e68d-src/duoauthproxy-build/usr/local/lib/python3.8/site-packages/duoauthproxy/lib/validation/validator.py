#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#
from collections import OrderedDict

import colorama
from twisted.internet import defer
from twisted.logger import FilteringLogObserver, LogLevel, LogLevelFilterPredicate

from duoauthproxy.lib import util
from duoauthproxy.lib.log import _sanitize_config
from duoauthproxy.lib.validation.config.check import cross_config
from duoauthproxy.lib.validation.config.config_toolbox import STANDARD_CONFIG_TOOLBOX
from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    ConfigCheckResult,
    SkippedSectionResult,
)
from duoauthproxy.lib.validation.connectivity.connectivity_toolbox import (
    STANDARD_TOOLBOX,
)
from duoauthproxy.lib.validation.test_resolver import (
    STANDARD_CONFIG_RESOLVER,
    STANDARD_CONNECTIVITY_RESOLVER,
)

NO_SECTIONS_MESSAGE = (
    "The Auth Proxy configuration has no sections - testing will be skipped."
)
CONNECTIVITY_TESTS_SKIPPED_MESSAGE = "Checks for external connectivity were not run. Please fix the configuration and try again."
SUCCESSFUL_VALIDATION_MESSAGE = "No issues detected"


@defer.inlineCallbacks
def check_config_and_connectivity(full_configuration, logger):
    validator = ConfigAndConnectivityValidator()
    results = yield validator.validate(full_configuration, logger)
    defer.returnValue(results)


@defer.inlineCallbacks
def check_config(
    full_configuration,
    logger,
    toolbox=STANDARD_CONFIG_TOOLBOX,
    resolver=STANDARD_CONFIG_RESOLVER,
):
    validator = ConfigAndConnectivityValidator(
        config_toolbox=toolbox,
        config_test_resolver=resolver,
        validate_connectivity=False,
    )
    config_results, _ = yield validator.validate(full_configuration, logger)
    defer.returnValue(config_results)


@defer.inlineCallbacks
def check_connectivity(
    full_configuration,
    logger,
    toolbox=STANDARD_TOOLBOX,
    resolver=STANDARD_CONNECTIVITY_RESOLVER,
):
    validator = ConfigAndConnectivityValidator(
        connectivity_toolbox=toolbox,
        connectivity_test_resolver=resolver,
        validate_config=False,
    )
    _, connectivity_results = yield validator.validate(full_configuration, logger)
    defer.returnValue(connectivity_results)


class ConfigAndConnectivityValidator(object):
    # Key used to identify the cross config checks in the config results.
    CROSS_CONFIG_KEY = "cross_config"

    def __init__(
        self,
        config_toolbox=STANDARD_CONFIG_TOOLBOX,
        config_test_resolver=STANDARD_CONFIG_RESOLVER,
        connectivity_toolbox=STANDARD_TOOLBOX,
        connectivity_test_resolver=STANDARD_CONNECTIVITY_RESOLVER,
        cross_config_tester=cross_config.check_cross_config,
        validate_config=True,
        validate_connectivity=True,
    ):
        """
        Object responsible for executing and logging the config and connectivity
        validation tests.
        Args:
            config_toolbox (ConfigTestToolbox): Toolbox to use for config tests
            config_test_resolver (dict): map of section name to test method for config validation
            connectivity_toolbox (ConnectivityTestToolbox): Toolbox for connectivity tests
            connectivity_test_resolver (dict): map of section name to test method for connectivity tests
            cross_config_tester (callable[ConfigProvider, ConfigTestToolbox]): test method for cross-section config tests
            validate_config (bool): True if config validation should be run
            validate_connectivity (bool): True if connectivity validation should be run
        """
        self.config_toolbox = config_toolbox
        self.config_test_resolver = config_test_resolver
        self.connectivity_toolbox = connectivity_toolbox
        self.connectivity_test_resolver = connectivity_test_resolver
        self.cross_config_tester = cross_config_tester
        self.validate_config = validate_config
        self.validate_connectivity = validate_connectivity
        colorama.init()

    @defer.inlineCallbacks
    def validate(self, full_configuration, logger):
        config_results = {}
        connectivity_results = {}

        try:
            if self.validate_config:
                config_results = yield self._validate_config(full_configuration, logger)

            connectivity_tests_skipped = False
            if self.validate_connectivity:
                # If both config and connectivity are being validated, only run the
                # connectivity tests if there were no configuration errors.
                if self.validate_config and not all_sections_successful(config_results):
                    connectivity_tests_skipped = True
                else:
                    connectivity_results = yield self._validate_connectivity(
                        full_configuration, logger
                    )

            self._log_summary_section(
                config_results, connectivity_results, connectivity_tests_skipped, logger
            )
            defer.returnValue((config_results, connectivity_results))
        except Exception as error:
            util.set_stdout_color("red")
            logger.error(
                "There was a problem running the connectivity tool: {error}",
                error=error,
            )
            util.set_stdout_color("reset")
            defer.returnValue(({}, {}))

    @defer.inlineCallbacks
    def _validate_config(self, full_configuration, logger):
        config_results = yield self._validate(
            full_configuration, logger, self.config_toolbox, self.config_test_resolver
        )
        cross_config_result = self.cross_config_tester(full_configuration)
        config_results.update({self.CROSS_CONFIG_KEY: cross_config_result})
        defer.returnValue(config_results)

    @defer.inlineCallbacks
    def _validate_connectivity(self, full_configuration, logger):
        connectivity_results = yield self._validate(
            full_configuration,
            logger,
            self.connectivity_toolbox,
            self.connectivity_test_resolver,
        )
        defer.returnValue(connectivity_results)

    @defer.inlineCallbacks
    def _validate(self, full_configuration, logger, toolbox, section_test_resolver):
        """
        Test the provided Auth Proxy configuration with the given resolver and toolbox

        Args:
            full_configuration (ConfigProvider): the Auth Proxy configuration to test
            logger (Logger): the twisted Logger to output results into
            toolbox: A class with all the toolbox methods needed by a resolvers check modules
            section_test_resolver (BaseTestResolver): Provides the testing function for a section name

        Returns:
            OrderedDict: The assembled results of the testing keyed by section name

        """
        sections = full_configuration.get_all_sections()

        if not sections:
            logger.warn(NO_SECTIONS_MESSAGE)
            defer.returnValue({})

        all_results = yield self._test_all_sections(
            sections, toolbox, section_test_resolver
        )

        self._output_results(all_results, sections, logger)
        defer.returnValue(all_results)

    @defer.inlineCallbacks
    def _test_all_sections(self, sections, toolbox, section_test_resolver):
        """
        Run the connectivity/config tests on all provided sections

        Args:
            sections (OrderedDict): The map of section name -> ConfigDict for the section, for all sections present
            toolbox (ConnectivityTestToolbox or ConfigTestToolbox): the test toolbox
            section_test_resolver (BaseTestResolver): Provides the testing function for a section name

        Returns:
            OrderedDict: the results of testing, mapped from section_name -> ReportableResult appropriate to that section

        """
        all_results = OrderedDict()

        for section_name, section_config in sections.items():
            section_tester = section_test_resolver.find_tester(section_name)
            section_result = yield self._test_one_section(
                section_config, toolbox, section_tester
            )
            all_results[section_name] = section_result

        defer.returnValue(all_results)

    @defer.inlineCallbacks
    def _test_one_section(self, section_config, toolbox, section_tester):
        """
        Test one configuration section

        Args:
            section_config (ConfigDict): The section's config
            toolbox (ConnectivityTestToolbox): The toolbox for the individual tests
            section_tester (func): The function to call to test the section

        Returns:
            ReportableResult: The result of the section test

        """
        result = yield defer.maybeDeferred(
            section_tester, section_config, toolbox=toolbox
        )
        defer.returnValue(result)

    def _output_results(self, all_results, sections, logger):
        """
        Output the results into a Logger

        Args:
            all_results (OrderedDict): map of section name -> ReportableResult subclass appropriate to the section
            logger (Logger): the twisted Logger to output into
        """
        for section_name, section_result in all_results.items():
            logger.info(
                "Testing section '{section_name}' with configuration:",
                section_name=section_name,
            )
            logger.info(
                "{cfg}",
                cfg=_sanitize_config(
                    sections[section_name],
                    lambda x: x.startswith("radius_secret")
                    or x.startswith("secret")
                    or x
                    in (
                        "skey",
                        "skey_protected",
                        "service_account_password",
                        "service_account_password_protected",
                    ),
                ),
            )
            if not section_result.is_successful() or section_result.is_warning():
                util.set_stdout_color("red")
            else:
                util.set_stdout_color("green")
            section_result.to_log_output(logger)
            util.set_stdout_color("reset")
            logger.info("-----------------------------")

    def _log_summary_section(
        self, config_results, connectivity_results, connectivity_tests_skipped, logger
    ):
        """
        Logs the summary section of the results.

        Args:
            config_results (dict): map of section name to section result for the config validation
            connectivity_results (dict): map of section name to section result for the connectivity validation
            connectivity_tests_skipped (bool): True if the connectivity tests were skipped due to config errors
            logger (Logger): the Twisted logger to write to

        """
        logger.info("SUMMARY")
        successful = all_sections_successful(
            config_results
        ) and all_sections_successful(connectivity_results)
        has_warnings = any_section_is_warning(config_results) or any_section_is_warning(
            connectivity_results
        )

        if successful and not has_warnings:
            util.set_stdout_color("green")
            logger.info("No issues detected")
            util.set_stdout_color("reset")
        else:
            if connectivity_tests_skipped:
                logger.warn(CONNECTIVITY_TESTS_SKIPPED_MESSAGE)
            logger.info(" ")
            self._log_summary_for_results(config_results, connectivity_results, logger)

    def _log_summary_for_results(self, config_results, connectivity_results, logger):
        """
        Logs the summaries of the config and connectivity results for the
        tested sections

        Args:
            config_results (dict): map of section name to section result for the config validation
            connectivity_results (dict): map of section name to section result for the connectivity validation
            logger (Logger): the Twisted logger to write to

        """

        # Wrap the logger's observer inside a FilteringLogObserver so we can
        # control the minimum log level that gets printed via a predicate.
        filtering_predicate = LogLevelFilterPredicate()
        original_observer = logger.observer
        logger.observer = FilteringLogObserver(original_observer, [filtering_predicate])

        # Print the cross config results first.
        cross_config_result = config_results.get(self.CROSS_CONFIG_KEY)
        if cross_config_result and self._has_summary_to_print(cross_config_result):
            self._log_section_summary(
                [cross_config_result],
                logger,
                filtering_predicate,
                "Cross-section results",
            )

        # Then log the summaries for the real config sections
        self._log_section_summaries(
            config_results, connectivity_results, logger, filtering_predicate
        )
        # Put the logger's observer back to its original value
        logger.observer = original_observer

    def _log_section_summaries(
        self, config_results, connectivity_results, logger, filtering_predicate
    ):
        """
        Logs the summaries for each config section that has warnings or errors.
        Args:
            config_results (dict): map of section name to section result for the config validation
            connectivity_results (dict): map of section name to section result for the connectivity validation
            logger (Logger): the Twisted logger to write to
            filtering_predicate (ILogFilterPredicate): Predicate used to filter
                the output to only include warnings and errors
        """
        config_sections = list(config_results.keys())
        # If the config was validated, remove the cross-config key from the
        # set of keys to iterate. This method prints out the results for real
        # config sections. Cross-config results are logged in _log_summary_for_results.
        if self.validate_config:
            config_sections.remove(self.CROSS_CONFIG_KEY)

        tested_sections = set().union(config_sections, connectivity_results.keys())
        for section in tested_sections:
            # Default to empty successful result objects so we can unconditionally
            # call to_log_output on config_result and connectivity_result
            config_result = config_results.get(section, ConfigCheckResult([]))
            connectivity_result = connectivity_results.get(
                section, SkippedSectionResult()
            )
            if self._has_summary_to_print(config_result) or self._has_summary_to_print(
                connectivity_result
            ):
                header = "Section [{section}]".format(section=section)
                section_results = [config_result, connectivity_result]
                self._log_section_summary(
                    section_results, logger, filtering_predicate, header
                )

    def _log_section_summary(self, results, logger, filtering_predicate, header):
        """
        Prints the results for a single config section in the summary. Only
        warnings and errors are printed.

        Args:
            results (list of BaseResult): Results to print in the section
            logger (Logger): the Twisted logger to write to
            filtering_predicate (ILogFilterPredicate): Predicate used to filter
                the output to only include warnings and errors
            header (str): The section header
        """
        logger.info(header)
        # Set the predicate to filter anything that isn't a warning or error
        # while we log the section result. Then clear predicate log level
        # once we're done.
        filtering_predicate.setLogLevelForNamespace(None, LogLevel.warn)
        util.set_stdout_color("red")
        for result in results:
            result.to_log_output(logger)
        util.set_stdout_color("reset")
        filtering_predicate.clearLogLevels()
        logger.info(" ")

    def _has_summary_to_print(self, result):
        """
        Args:
            result (BaseResult): The result for a single section

        Returns:
            bool: True if the result should be printed in the summary section
        """
        return result and (not result.is_successful() or result.is_warning())


def any_section_is_warning(full_results):
    """
    Args:
        full_results (dict): dict of {'section_name': BaseResult children}

    Returns:
        bool: True if any result is a warning, false otherwise
    """
    return any(result.is_warning() for result in iter(full_results.values()))


def all_sections_successful(full_results) -> bool:
    """
    Args:
        full_results (dict): dict of {'section_name': BaseResult children}
    Returns:
        True if all results are successful
        False if any section fails
    """
    return all(res.is_successful() for res in iter(full_results.values()))
