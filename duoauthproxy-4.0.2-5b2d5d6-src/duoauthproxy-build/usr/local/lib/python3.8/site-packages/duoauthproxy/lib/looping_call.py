"""
Simple looping call wrapper which allows for the reactor to be easily
overriden in the constructor. If no clock is provided the reactor is used
"""
from twisted.internet import task


class LoopingCall(task.LoopingCall):
    def __init__(self, f, clock=None):
        super(LoopingCall, self).__init__(f)
        if clock:
            self.clock = clock

    def stop(self):
        if self.running:
            super(LoopingCall, self).stop()
