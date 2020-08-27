#
# Copyright (c) 2017 Duo Security
# All Rights Reserved
# All Wrongs Reversed
#
import time

from duoauthproxy.lib.validation.connectivity.connectivity_results import (
    DuoPingResult,
    TimeDriftResult,
    ValidateApiCredentialsResult,
)

MAX_TIME_DRIFT_IN_SECONDS = 60


"""Module for determining if the Authproxy can reach out to Duo
via Duo API Calls
"""


def can_ping_duo(api_client):
    """Ping the Duo service through the Duo api and a DuoPingResult.
    Args:
        api_client: a Duo api client
    Returns:
        DuoPingResult: result of the test
    """

    start = time.time()

    try:
        api_client.ping()
    except Exception as e:
        return DuoPingResult(False, api_client.host, exception=e)

    end = time.time()
    latency_time = (end - start) * 1000.0

    return DuoPingResult(True, api_client.host, latency_time)


def can_validate_duo_creds(api_client):
    """Invokes AuthAPI's /check to validate the user's ikey/skey/api-host.
    Args:
        api_client: a Duo api client
    Returns:
        ValidateApiCredentialsResult: the result of the test
    """
    try:
        api_client.check()
    except Exception as e:
        return ValidateApiCredentialsResult(
            False, api_client.host, api_client.ikey, exception=e
        )

    return ValidateApiCredentialsResult(True, api_client.host, api_client.ikey)


def has_acceptable_time_drift(api_client):
    """Detects the time drift between the Duo cloud and the server running the Auth Proxy. It
    compares the Duo cloud system time retrieved via a ping and the server running the Auth Proxy.
    Args:
        api_client: Duo API client
    Returns:
        Dict: [result] True/False
              [drift_in_seconds] Integer
    """

    try:
        response = api_client.ping()
    except Exception as error:
        return TimeDriftResult(False, 0, exception=error)

    time_drift = abs(time.time() - response["time"])
    result = time_drift < MAX_TIME_DRIFT_IN_SECONDS

    return TimeDriftResult(result, time_drift)
