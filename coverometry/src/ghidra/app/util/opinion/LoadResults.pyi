from typing import Iterator
import ghidra.app.util.importer
import ghidra.app.util.opinion
import ghidra.framework.model
import ghidra.util.task
import java.lang
import java.util
import java.util.function


class LoadResults(object, java.lang.Iterable):
    """
    The result of a 
     Loader#load(ghidra.app.util.bin.ByteProvider, String, Project, String, LoadSpec, List, MessageLog, Object, TaskMonitor).
     A LoadResults object provides convenient access to and operations on the underlying 
     Loaded DomainObjects that got loaded.
    """





    @overload
    def __init__(self, __a0: List[object]): ...

    @overload
    def __init__(self, __a0: ghidra.framework.model.DomainObject, __a1: unicode, __a2: unicode): ...

    def __iter__(self): ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getPrimary(self) -> ghidra.app.util.opinion.Loaded:
        """
        Gets the "primary" {@link Loaded} {@link DomainObject}, who's meaning is defined by each 
         {@link Loader} implementation
        @return The "primary" {@link Loaded} {@link DomainObject}
        """
        ...

    def getPrimaryDomainObject(self) -> object:
        """
        Gets the "primary" {@link DomainObject}, who's meaning is defined by each {@link Loader} 
         implementation
        @return The "primary" {@link DomainObject}
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.app.util.opinion.Loaded]: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def release(self, consumer: object) -> None:
        """
        Notify all of the {@link Loaded} {@link DomainObject}s that the specified consumer is no 
         longer using them. When the last consumer invokes this method, the {@link Loaded} 
         {@link DomainObject}s will be closed and will become invalid.
        @param consumer the consumer
        """
        ...

    @overload
    def release(self, consumer: object, filter: java.util.function.Predicate) -> None:
        """
        Notify the filtered {@link Loaded} {@link DomainObject}s that the specified consumer is no 
         longer using them. When the last consumer invokes this method, the filtered {@link Loaded} 
         {@link DomainObject}s will be closed and will become invalid.
        @param consumer the consumer
        @param filter a filter to apply to the {@link Loaded} {@link DomainObject}s prior to the
           release
        """
        ...

    def releaseNonPrimary(self, consumer: object) -> None:
        """
        Notify the non-primary {@link Loaded} {@link DomainObject}s that the specified consumer is no 
         longer using them. When the last consumer invokes this method, the non-primary {@link Loaded} 
         {@link DomainObject}s will be closed and will become invalid.
        @param consumer the consumer
        """
        ...

    def save(self, project: ghidra.framework.model.Project, consumer: object, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        {@link Loaded#save(Project, MessageLog, TaskMonitor) Saves} each {@link Loaded} 
         {@link DomainObject} to the given {@link Project}.
         <p>
         NOTE: If any fail to save, none will be saved (already saved {@link DomainFile}s will be
         cleaned up/deleted), and all {@link Loaded} {@link DomainObject}s will have been
         {@link #release(Object) released}.
        @param project The {@link Project} to save to
        @param consumer the consumer
        @param messageLog The log
        @param monitor A cancelable task monitor
        @throws CancelledException if the operation was cancelled
        @throws IOException If there was a problem saving
        @see Loaded#save(Project, MessageLog, TaskMonitor)
        """
        ...

    def size(self) -> int:
        """
        Gets the number of {@link Loaded} {@link DomainObject}s in this {@link LoadResults}.  The
         size will always be greater than 0.
        @return The number of {@link Loaded} {@link DomainObject}s in this {@link LoadResults}
        """
        ...

    def spliterator(self) -> java.util.Spliterator: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def primary(self) -> ghidra.app.util.opinion.Loaded: ...

    @property
    def primaryDomainObject(self) -> ghidra.framework.model.DomainObject: ...