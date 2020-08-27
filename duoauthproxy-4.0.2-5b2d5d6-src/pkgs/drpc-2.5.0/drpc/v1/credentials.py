class DrpcCredentials(object):
    def __init__(self, identity, secret):
        self.identity = identity
        self.secret = secret

    def sign(self, message):
        raise NotImplementedError

    def verify_signature(self, message, signed_message):
        raise NotImplementedError

    def get_identity(self):
        return self.identity

    def get_secret(self):
        return self.secret
