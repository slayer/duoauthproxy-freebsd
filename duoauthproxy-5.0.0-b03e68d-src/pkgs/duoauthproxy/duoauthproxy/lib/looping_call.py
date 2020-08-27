"""
Simple looping call wrapper which allows for the reactor to be easily
overriden in the constructor. If no clock is provided the reactor is used
"""
import itertools
from typing import Optional

from twisted.internet import defer, task


class LoopingCall(task.LoopingCall):
    def __init__(self, f, clock=None):
        super(LoopingCall, self).__init__(f)
        if clock:
            self.clock = clock

    def stop(self):
        if self.running:
            super(LoopingCall, self).stop()


class ExponentialBackoffCall:
    _deferred = None
    backoff_rate = None
    call = None
    interval = None
    maximum_wait = None
    running = False
    starting_interval = None

    def __init__(self, f, *a, **kw):
        self.f = f
        self.a = a
        self.kw = kw
        from twisted.internet import reactor

        self.clock = reactor
        self.calls = 0

    def start(
        self,
        interval: float,
        backoff_rate: float,
        maximum_wait: Optional[float] = None,
        now: bool = True,
    ):
        """ Starts a looping call with an expontential backoff

        Args:
            interval (float): seconds to wait between calls initially
            backoff_rate (float): factor to increase interval by after each call
            maximum_wait Optional(float): maximum time to wait between any two calls
            now (bool): make call immediately

        Returns:
            @return: A Deferred whose callback will be invoked with
            C{self} when C{self.stop} is called, or whose errback will be
            invoked when the function raises an exception or returned a
            deferred that has its errback invoked.
        """

        assert (
            not self.running
        ), "Tried to start an already running ExponentialBackoffCall."
        if interval <= 0:
            raise ValueError("interval must be > 0")
        if backoff_rate <= 1:
            raise ValueError("backoff must be > 1")
        self.running = True

        # Loop might fail to start and then self._deferred will be cleared.
        # This why the local C{deferred} variable is used.
        deferred = self._deferred = defer.Deferred()
        self.backoff_rate = backoff_rate
        self.maximum_wait = maximum_wait
        self.starting_interval = interval
        self.interval = self._interval(self.starting_interval, self.backoff_rate)

        if now:
            self.run_callback()
        else:
            self.schedule()
        return deferred

    def _interval(self, interval, backoff_rate):
        for step in itertools.count():
            yield interval * backoff_rate ** step

    def stop(self):
        self.running = False
        if self.call is not None:
            self.call.cancel()
            self.call = None
            d, self._deferred = self._deferred, None
            d.callback(self)

    def reset(self):
        if self.call is not None:
            self.call.cancel()
            self.call = None
            self.interval = self._interval(self.starting_interval, self.backoff_rate)
            self.schedule()

    def run_callback(self):
        self.call = None
        d = defer.maybeDeferred(self.f, *self.a, **self.kw)
        d.addBoth(self.schedule)

    # dummy parameter required for using as a deferred callback
    def schedule(self, _=None):
        time_to_wait = next(self.interval)
        if self.maximum_wait and self.maximum_wait < time_to_wait:
            time_to_wait = self.maximum_wait
        self.call = self.clock.callLater(time_to_wait, self.run_callback)
