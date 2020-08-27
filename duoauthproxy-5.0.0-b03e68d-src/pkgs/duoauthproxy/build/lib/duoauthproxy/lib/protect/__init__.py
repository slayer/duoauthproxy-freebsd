#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

try:
    import win32crypt

    PROTECT_ENABLED = True
except ImportError:
    PROTECT_ENABLED = False

import base64

__entropy = b"AU$HPRO$Y"
CRYPTPROTECT_UI_FORBIDDEN = 0x01
CRYPTPROTECT_LOCAL_MACHINE = 0x04


class ProtectDisabledException(Exception):
    pass


def protect(plain_text: str) -> str:
    """Protects a sensitive string, such as a password, for persistence.
    Currently only available if in certain environments.
    Check protect.PROTECT_ENABLED for availability."""

    if not PROTECT_ENABLED:
        raise ProtectDisabledException()

    description = "win32crypto.py"
    reserved_field = None
    prompt_struct = None
    flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE
    cipher_text = win32crypt.CryptProtectData(
        plain_text.encode(),
        description,
        __entropy,
        reserved_field,
        prompt_struct,
        flags,
    )
    return base64.b64encode(cipher_text).decode()


def unprotect(cipher_text: str) -> str:
    """Unprotects a previously protected string.
    Currently only available if in certain environments.
    Check protect.PROTECT_ENABLED for availability."""

    if not PROTECT_ENABLED:
        raise ProtectDisabledException()

    cipher_text_bytes = base64.b64decode(cipher_text)
    reserved_field = None
    prompt_struct = None
    flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE
    _, plainText = win32crypt.CryptUnprotectData(
        cipher_text_bytes, __entropy, reserved_field, prompt_struct, flags
    )
    return plainText.decode()
