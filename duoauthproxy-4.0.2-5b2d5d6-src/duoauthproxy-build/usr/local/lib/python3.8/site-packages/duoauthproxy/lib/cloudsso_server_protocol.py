import drpc.v2 as drpc

# protocol's factory of its termination by default. We could then just handle any callbacks
# in the factory.


class CloudSSOServerProtocol(drpc.ServerProtocol):
    def connectionLost(self, reason):
        super(CloudSSOServerProtocol, self).connectionLost(reason)
        self.factory.connectionLost(reason)
