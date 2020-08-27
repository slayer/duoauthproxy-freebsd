#
# Copyright (c) 2019 Duo Security
# All Rights Reserved
#
"""
Utility for storing and retrieving secrets
"""
import json
import os
from typing import Any, Callable, List, TypeVar

import six

from duoauthproxy.lib import log, protect, util

LINUX_STORAGE_PATHS = [
    os.path.join(os.sep, "etc", "duoauthproxy", "secrets"),
    os.path.join(util.get_home_dir(), "conf", ".secrets"),
]
WINDOWS_STORAGE_PATHS = [
    os.path.join("C:", os.sep, "programdata", "Duo Authentication Proxy", "secrets"),
    os.path.join(util.get_home_dir(), "conf", "secrets"),
]
MAX_IO_RETRY_COUNT = 3

PROXY_COUNTER_KEY = "proxy_counter"


class SecretStorageError(Exception):
    pass


class SecretStorageDataError(SecretStorageError):
    pass


class SecretStorageFileError(SecretStorageError):
    pass


# this ensures the decorator isn't modifying the return type
T = TypeVar("T")


def error_resistant_file_access(access_func: Callable[..., T]) -> Callable[..., T]:
    """ Decorator for "safely" accessing a secret storage file.
    Will retry a failed IO a few times to avoid transient issues.
    Args:
        access_func (func): Function that will perform the file operations
            like opening, reading, and writing data.
    Raises
    """

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        retry_attempts = 0
        while True:
            try:
                return access_func(*args, **kwargs)
            except KeyError as ke:
                raise ke
            except IOError as ioe:
                if retry_attempts < MAX_IO_RETRY_COUNT - 1:
                    retry_attempts += 1
                    continue
                else:
                    raise ioe

    return wrapped


def decrypt_secret(secret: str) -> str:
    """
    Decrypt a string if protect is not available we just return back the input.
        Args:
            secret (str)
        Returns:
            protected_secret (str)
    """
    if not protect.PROTECT_ENABLED:
        return secret

    try:
        return protect.unprotect(secret)
    except Exception as e:
        raise SecretStorageDataError("Unable to decrypt secret.", e)


def encrypt_secret(secret: str) -> str:
    """
    If protect is available encrypt the str otherwise return back the input
        Args:
            secret (str)
        Returns:
            protected_secret (str)
    """
    if not protect.PROTECT_ENABLED:
        return secret

    try:
        return protect.protect(secret)
    except Exception as e:
        raise SecretStorageDataError("Unable to encrypt secret.", e)


def store_secret(identifier: str, secret: str) -> None:
    """
    Store a secret string in a secure fashion, so it can retrieved later

    Args:
        identifier (str): an identifier for the secret
        secret (str): the (non-blank) secret to store

    Raises:
          IOError if anything goes wrong
    """
    filename = get_storage_filename()
    _write_secret(filename, identifier, secret)


def retrieve_secret(identifier: str) -> str:
    """
    Retrieve a stored secret

    Args:
        identifier (str): The identifier of the secret

    Returns:
        (str) the stored secret

    Raises:
        IOError if anything goes wrong

    """
    filename = get_storage_filename()
    return _read_secret(filename, identifier)


def access_proxy_counter() -> str:
    """
    Atomically increment the 'proxy_counter' in the secret store.

    Returns:
        (str) The new value of the 'proxy_counter'

    Raises:
        Propagates IOError from store() or retrieve()
    """
    try:
        current_value = int(retrieve_secret(PROXY_COUNTER_KEY))
    except KeyError:
        current_value = 0

    new_value = six.text_type(current_value + 1)

    store_secret(PROXY_COUNTER_KEY, new_value)

    return new_value


@error_resistant_file_access
def _read_secret(filename: str, identifier: str) -> str:
    """ Actually opens the file and reads
    Returns:
        str: data at the identifier
    Raises:
        IOError: couldn't read
        KeyError: read, but couldn't find the specified key
    """
    with open(filename, "r") as fh:
        data = json.load(fh)

    if identifier not in data:
        raise KeyError("Could not find {0} in secret storage".format(identifier))

    return decrypt_secret(data[identifier])


@error_resistant_file_access
def _write_secret(filename: str, identifier: str, secret: str) -> None:
    """ Actually opens the file and writes
    Raises:
        IOError: couldn't write successfully
    """
    value_to_write = encrypt_secret(secret)

    with open(filename, "a+") as fh:
        try:
            fh.seek(0)
            data = json.load(fh)
        except json.decoder.JSONDecodeError:
            raise SecretStorageDataError(
                "Invalid JSON detected in secret storage. Please clear out storage file and try again."
            )

        try:
            data[identifier] = value_to_write
            serialized_secrets = json.dumps(data)
        except (TypeError, json.decoder.JSONDecodeError):
            raise SecretStorageDataError(
                "Attempted to write invalid JSON to secret storage. Aborting update."
            )
        else:
            fh.truncate(0)
            fh.write(serialized_secrets)


def restrict_permissions(path: str) -> None:
    """
    Restricts the permissions on a file to something reasonably secure on both linux
    and windows

    args:
        path (str): Path to file to secure. Does not work on directories
    """

    if util.is_windows_os():
        import win32api
        import win32con

        if os.path.exists(path):
            existing_attributes = win32api.GetFileAttributes(path)
            win32api.SetFileAttributes(
                path, existing_attributes | win32con.FILE_ATTRIBUTE_HIDDEN
            )
    else:
        if os.path.isdir(path):
            os.chmod(path, 0o700)
        elif os.path.isfile(path):
            os.chmod(path, 0o600)


def make_storage(path: str) -> None:
    directory = os.path.dirname(path)
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            restrict_permissions(directory)
        except Exception as e:
            raise IOError(e)

    try:
        with open(path, "w+") as fh:
            json.dump({}, fh)
    except Exception as e:
        raise IOError(e)
    else:
        restrict_permissions(path)


def is_writable(path: str) -> bool:
    """
    Does not create a file but checks to see if one exists and if it's writable
    args:
        path (str): path to the file to check
    """

    try:
        if os.path.isfile(path):
            with open(path, "a"):
                return True
        else:
            return False
    except Exception as e:
        log.msg(e)
        return False


def _get_storage_paths() -> List[str]:
    if util.is_windows_os():
        storage_paths = WINDOWS_STORAGE_PATHS
    else:
        storage_paths = LINUX_STORAGE_PATHS

    return storage_paths


def get_storage_filename() -> str:
    return _find_usable_path(_get_storage_paths())


def _find_usable_path(storage_paths: List[str]) -> str:
    """
    Returns the file path of the first writable storage location. The file is guarenteed
    to exist and be writable if it is returned from this function. If an exception is thrown
    there may be no storage location available
    """

    for path in storage_paths:
        if is_writable(path):
            return path

    for path in storage_paths:
        try:
            make_storage(path)
            return path
        except Exception as e:
            log.msg(e)

    raise SecretStorageFileError(
        "No writable storage locations found. Make sure you have the privilege to write."
    )
