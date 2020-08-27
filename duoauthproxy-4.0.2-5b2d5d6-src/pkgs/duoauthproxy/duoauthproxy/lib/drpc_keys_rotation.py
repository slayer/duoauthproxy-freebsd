#
# Copyright (c) 2019 Duo Security
# All Rights Reserved
#

from twisted.internet import defer

from duoauthproxy.lib import duo_async, log

from drpc.v2 import crypto as drpc_crypto


@defer.inlineCallbacks
def rotate_skeys(duo_client):
    """
    Generate new DRPC skeys (signing and encryption) via ECDHE with the Duo cloud service.

    Args:
        duo_client (CloudSSODuoClient): a duo client with the current credentials

    Returns:
        (signing_skey, encryption_skey) tuple with the new keys as bytes, or reraises API errors

    """
    proxy_public_key, proxy_private_key = drpc_crypto.generate_ephemeral_keys()
    try:
        ser_proxy_public_key = drpc_crypto.serialize_ephemeral_key(proxy_public_key)
        rotate_result = yield duo_client.proxy_rotate_skeys(ser_proxy_public_key)
        duo_public_key = drpc_crypto.deserialize_ephemeral_key(rotate_result['duo_public_key'])
    except duo_async.DuoAPIError as e:
        log.err(e, 'Rotate call failed')
        raise e

    new_signing_skey_bytes, new_encryption_skey_bytes = drpc_crypto.derive_shared_keys(duo_public_key, proxy_private_key)

    defer.returnValue((new_signing_skey_bytes, new_encryption_skey_bytes))
