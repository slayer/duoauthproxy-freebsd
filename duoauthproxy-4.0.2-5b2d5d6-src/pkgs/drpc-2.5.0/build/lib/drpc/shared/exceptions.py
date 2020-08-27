""" The purpose of this module is to contain all shared exceptions between the versions of DRPC.
This allows application code to raise and except on just one type of exception. Especially useful when writing
code that is meant to be compatible with multiple versions of DRPC. """

ERR_BAD_ARG = 'bad arg'
ERR_CONNECTION_LOST = 'connection lost'
ERR_MISSING_ARG = 'missing arg'
ERR_SERIALIZE_RESULT = 'cannot serialize result'
ERR_TIMEOUT = 'timeout'
ERR_UNKNOWN = 'unknown error'


class CallError(Exception):
    """
    Errors with a one-to-one correspondence between local and
    RPC-serialized representation.
    """

    def __init__(self, error, error_args=None):
        self.error = error
        if not error_args:
            error_args = {}
        self.error_args = error_args
        super(CallError, self).__init__(error, error_args)

    def __eq__(self, other):
        return (self.error == other.error
                and self.error_args == other.error_args)


class CallBadArgError(CallError):
    def __init__(self, args):
        super(CallBadArgError, self).__init__(
            error=ERR_BAD_ARG,
            error_args={
                'args': args,
            },
        )


class CallMissingArgError(CallError):
    def __init__(self, args):
        super(CallMissingArgError, self).__init__(
            error=ERR_MISSING_ARG,
            error_args={
                'args': args,
            },
        )
