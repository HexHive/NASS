import java.lang


class FileSystemSynchronizer(object):
    """
    This class is essentially a global flag used to track the long running file system synchronizing
     operation.   This class is a workaround to avoid rewriting the complicated file system locking.
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isSynchronizing() -> bool:
        """
        Returns true the underlying file system is going through a long-running synchronization 
         operation while holding the {@code filesystem} lock.   Calling this method allows clients
         in the Swing thread to avoid  calling methods that require a file system lock, which would
         cause the UI to lock during the synchronizing operation.
        @return true if synchronizing
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def setSynchronizing(b: bool) -> None:
        """
        Sets whether the synchronizing operation is running.
        @param b true if synchronizing
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

