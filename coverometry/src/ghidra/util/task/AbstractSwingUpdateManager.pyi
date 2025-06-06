import java.lang


class AbstractSwingUpdateManager(object):
    """
    A base class to allow clients to buffer events.  UI components may receive numbers events to make
     changes to their underlying data model.  Further, for many of these clients, it is sufficient
     to perform one update to capture all of the changes.  In this scenario, the client can use this
     class to keep pushing off internal updates until: 1) the flurry of events has settled down, or
     2) some specified amount of time has expired.
 
     The various methods dictate when the client will get a callback:
 
     	#update() - if this is the first call to update, then do the work
                              immediately; otherwise, buffer the update request until the
                              timeout has expired.
      #updateNow() - perform the callback now.
      #updateLater() - buffer the update request until the timeout has expired.
      Non-blocking update now - this is a conceptual use-case, where the client wishes to perform an
                              immediate update, but not during the current Swing event.  To achieve
                              this, you could call something like:
                          
  
 

      This class is safe to use in a multi-threaded environment.   State variables are guarded
     via synchronization on this object.   The Swing thread is used to perform updates, which
     guarantees that only one update will happen at a time.
    """

    DEFAULT_MAX_DELAY: int = 30000
    DEFAULT_MIN_DELAY: int = 250







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

    @property
    def busy(self) -> bool: ...

    @property
    def disposed(self) -> bool: ...