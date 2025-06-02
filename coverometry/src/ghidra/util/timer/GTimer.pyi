import ghidra.util.timer
import java.lang


class GTimer(object):
    """
    A class to schedule Runnables to run after some delay, optionally repeating.  This class
     uses a Timer internally to schedule work.   Clients of this class are given a monitor
     that allows them to check on the state of the runnable, as well as to cancel the runnable.
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def scheduleRepeatingRunnable(delay: long, period: long, callback: java.lang.Runnable) -> ghidra.util.timer.GTimerMonitor:
        """
        Schedules a runnable for <b>repeated</b> execution after the specified delay. A delay value
         less than 0 will cause this timer to schedule nothing.  This allows clients to use this
         timer class with no added logic for managing timer enablement.
        @param delay the time (in milliseconds) to wait before executing the runnable.   A negative
                value signals not to run the timer--the callback will not be executed
        @param period time in milliseconds between successive runnable executions
        @param callback the runnable to be executed
        @return a GTimerMonitor which allows the caller to cancel the timer and check its status
        @throws IllegalArgumentException if {@code period <= 0}
        """
        ...

    @staticmethod
    def scheduleRunnable(delay: long, callback: java.lang.Runnable) -> ghidra.util.timer.GTimerMonitor:
        """
        Schedules a runnable for execution after the specified delay.   A delay value less than 0
         will cause this timer to schedule nothing.  This allows clients to use this timer class
         with no added logic for managing timer enablement.
        @param delay the time (in milliseconds) to wait before executing the runnable.  A negative
                value signals not to run the timer--the callback will not be executed
        @param callback the runnable to be executed.
        @return a GTimerMonitor which allows the caller to cancel the timer and check its status.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

