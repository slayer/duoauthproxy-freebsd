from drpc.v2.credentials import DrpcCredentials


class DuoCreds(object):
    def __init__(self, identity: str, secret: bytes) -> None:
        if not isinstance(secret, bytes):
            raise Exception('Expected type bytes for secret, got {} instead'.format(type(secret)))

        self.identity = identity
        self.secret = secret

    def get_identity(self) -> str:
        return self.identity

    def get_secret(self) -> bytes:
        return self.secret

    def create_drpc_credentials(self) -> DrpcCredentials:
        return DrpcCredentials(self.identity, self.secret)
