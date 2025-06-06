import ghidra.framework.main.logviewer.event
import java.lang
import java.util


class FVEventListener(java.util.Observable):
    """
    Extension of the Java Observer class that allows clients to send FVEvent
     messages to subscribers.

     Note: this 'listener' class serves as an event 'hub', where clients can push events to this
     class and register to receive events from this class.   The events given to this listener are
     heterogeneous and serve as a general message passing system for this API.   This class should
     be replaced by simple object communication by using normal method calls.
    """





    def __init__(self): ...



    def addObserver(self, __a0: java.util.Observer) -> None: ...

    def countObservers(self) -> int: ...

    def deleteObserver(self, __a0: java.util.Observer) -> None: ...

    def deleteObservers(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hasChanged(self) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def notifyObservers(self) -> None: ...

    @overload
    def notifyObservers(self, __a0: object) -> None: ...

    def send(self, evt: ghidra.framework.main.logviewer.event.FVEvent) -> None:
        """
        Fires off the given {@link FVEvent} using the appropriate {@link Observer} methods.
        @param evt
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

