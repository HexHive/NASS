import ghidra.util.task
import java.lang


class BufferedSwingRunner(ghidra.util.task.AbstractSwingUpdateManager):
    """
    A class that run the client's runnable on the Swing thread.  Repeated requests will get buffered
     until the max delay is reached.
    """





    @overload
    def __init__(self): ...

    @overload
    def __init__(self, minDelay: int, maxDelay: int):
        """
        Constructs a new SwingUpdateManager
         <p>
         <b>Note: </b>The <code>minDelay</code> will always be at least {@link #MIN_DELAY_FLOOR}, 
         regardless of the given value.
        @param minDelay the minimum number of milliseconds to wait once the event stream stops
                         coming in before actually updating the screen.
        @param maxDelay the maximum amount of time to wait between gui updates.
        """
        ...



    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def flush(self) -> None:
        """
        Causes this run manager to run if it has a pending update
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def hasPendingUpdates(self) -> bool:
        """
        Returns true if there is a pending request that hasn't started yet.  Any currently
         executing requests will not affect this call.
        @return true if there is a pending request that hasn't started yet.
        """
        ...

    def hashCode(self) -> int: ...

    def isBusy(self) -> bool:
        """
        Returns true if any work is being performed or if there is buffered work
        @return true if any work is being performed or if there is buffered work
        """
        ...

    def isDisposed(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def run(self, r: java.lang.Runnable) -> None:
        """
        Runs the given runnable.  If this is the first call to <code>run</code>, then do the work
         immediately; otherwise, buffer the request until the timeout has expired.
 
         <p>See the header of {@link AbstractSwingUpdateManager} for details on the update process.
        @param r the task to run on the Swing thread
        """
        ...

    def runLater(self, r: java.lang.Runnable) -> None:
        """
        Runs the given runnable later, buffering the request until the timeout has expired.
 
         <p>See the header of {@link AbstractSwingUpdateManager} for details on the update process.
        @param r the task to run on the Swing thread
        """
        ...

    def stop(self) -> None:
        """
        Signals to stop any buffered work.   This will not stop any in-progress work.
        """
        ...

    def toString(self) -> unicode: ...

    def toStringDebug(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

