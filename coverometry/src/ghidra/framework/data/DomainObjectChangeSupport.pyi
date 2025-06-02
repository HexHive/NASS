import java.lang


class DomainObjectChangeSupport(object):
    """
    A class to queue and send DomainObjectChangeRecord events.
 
     For simplicity, this class requires all mutations to internal data structures to be locked using
     the internal write lock.  Clients are not required to use any synchronization when using this
     class.
 
     Internally, events are queued and will be fired on a timer.
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

