import ghidra.framework.store
import java.lang
import java.util.concurrent


class FileSystemEventManager(object, ghidra.framework.store.FileSystemListener):
    """
    FileSystemListenerList maintains a list of FileSystemListener's.
     This class, acting as a FileSystemListener, simply relays each callback to
     all FileSystemListener's within its list.  Employs either a synchronous 
     and asynchronous notification mechanism. Once disposed event dispatching will 
     discontinue.
    """





    def __init__(self, enableAsynchronousDispatching: bool):
        """
        Constructor
        @param enableAsynchronousDispatching if true a separate dispatch thread will be used
         to notify listeners.  If false, blocking notification will be performed.  Events are 
         immediately discarded in the absence of any listener(s).
        """
        ...



    def add(self, listener: ghidra.framework.store.FileSystemListener) -> None:
        """
        Add a listener to this list.
        @param listener the listener
        """
        ...

    def dispose(self) -> None:
        """
        Discontinue event dispatching and terminate dispatch thread if it exists.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def flushEvents(self, timeout: long, unit: java.util.concurrent.TimeUnit) -> bool:
        """
        Blocks until all current events have been processed.
         <p>
         Note: clients should only use this method when {@link #isAsynchronous()} returns true, since
         this class cannot track when non-threaded events have finished broadcasting to listeners.
         In a synchronous use case, any test that needs to know when client events have been processed
         must use some other mechanism to know when event processing is finished.
        @param timeout the maximum time to wait
        @param unit the time unit of the {@code time} argument
        @return true if the events were processed in the given timeout.  A false value will be
         returned if either a timeout occured
        """
        ...

    def folderCreated(self, parentPath: unicode, folderName: unicode) -> None: ...

    def folderDeleted(self, parentPath: unicode, folderName: unicode) -> None: ...

    def folderMoved(self, parentPath: unicode, folderName: unicode, newParentPath: unicode) -> None: ...

    def folderRenamed(self, parentPath: unicode, folderName: unicode, newFolderName: unicode) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isAsynchronous(self) -> bool:
        """
        Return true if asynchornous event processing is enabled.
        @return true if asynchornous event processing is enabled, else false
        """
        ...

    def itemChanged(self, parentPath: unicode, itemName: unicode) -> None: ...

    def itemCreated(self, parentPath: unicode, itemName: unicode) -> None: ...

    def itemDeleted(self, parentPath: unicode, itemName: unicode) -> None: ...

    def itemMoved(self, parentPath: unicode, name: unicode, newParentPath: unicode, newName: unicode) -> None: ...

    def itemRenamed(self, parentPath: unicode, itemName: unicode, newName: unicode) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self, listener: ghidra.framework.store.FileSystemListener) -> None:
        """
        Remove a listener from this list.
        @param listener the listener
        """
        ...

    def syncronize(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def asynchronous(self) -> bool: ...