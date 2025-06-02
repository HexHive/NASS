import ghidra.app.util.importer
import ghidra.framework.model
import ghidra.util.task
import java.lang


class Loaded(object):
    """
    A loaded DomainObject produced by a Loader.  In addition to storing the loaded
     DomainObject, it also stores the Loader's desired name and project folder path 
     for the loaded DomainObject, should it get saved to a project.
    """





    def __init__(self, __a0: ghidra.framework.model.DomainObject, __a1: unicode, __a2: unicode): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDomainObject(self) -> object:
        """
        Gets the loaded {@link DomainObject}
        @return The loaded {@link DomainObject}
        """
        ...

    def getName(self) -> unicode:
        """
        Gets the name of the loaded {@link DomainObject}.  If a 
         {@link #save(Project, MessageLog, TaskMonitor)} occurs, this will attempted to be used for
         the resulting {@link DomainFile}'s name.
        @return the name of the loaded {@link DomainObject}
        """
        ...

    def getProjectFolderPath(self) -> unicode:
        """
        Gets the project folder path this will get saved to during a 
         {@link #save(Project, MessageLog, TaskMonitor)} operation.
         <p>
         NOTE: The returned path will always end with a "/".
        @return the project folder path
        """
        ...

    def getSavedDomainFile(self) -> ghidra.framework.model.DomainFile:
        """
        Gets the loaded {@link DomainObject}'s associated {@link DomainFile} that was
         {@link #save(Project, MessageLog, TaskMonitor) saved}
        @return The loaded {@link DomainObject}'s associated saved {@link DomainFile}, or null if 
           was not saved
        @throws FileNotFoundException If the loaded {@link DomainObject} was saved but the associated
           {@link DomainFile} no longer exists
        @see #save(Project, MessageLog, TaskMonitor)
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def release(self, consumer: object) -> None:
        """
        Notify the loaded {@link DomainObject} that the specified consumer is no longer using it.
         When the last consumer invokes this method, the loaded {@link DomainObject} will be closed
         and will become invalid.
        @param consumer the consumer
        """
        ...

    def save(self, project: ghidra.framework.model.Project, messageLog: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> ghidra.framework.model.DomainFile:
        """
        Saves the loaded {@link DomainObject} to the given {@link Project} at this object's 
         project folder path, using this object's name.
         <p>
         If a {@link DomainFile} already exists with the same desired name and project folder path,
         the desired name will get a counter value appended to it to avoid a naming conflict.
         Therefore, it should not be assumed that the returned {@link DomainFile} will have the same
         name as a call to {@link #getName()}.
        @param project The {@link Project} to save to
        @param messageLog The log
        @param monitor A cancelable task monitor
        @return The {@link DomainFile} where the save happened
        @throws CancelledException if the operation was cancelled
        @throws ClosedException if the loaded {@link DomainObject} was already closed
        @throws IOException If there was an IO-related error, an invalid name was specified, or it
           was already successfully saved and still exists
        """
        ...

    def setProjectFolderPath(self, projectFolderPath: unicode) -> None:
        """
        Sets the project folder path this will get saved to during a
         {@link #save(Project, MessageLog, TaskMonitor)} operation.
        @param projectFolderPath The project folder path this will get saved to during a 
           {@link #save(Project, MessageLog, TaskMonitor)} operation.  If null or empty, the root 
           project folder will be used.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def domainObject(self) -> ghidra.framework.model.DomainObject: ...

    @property
    def name(self) -> unicode: ...

    @property
    def projectFolderPath(self) -> unicode: ...

    @projectFolderPath.setter
    def projectFolderPath(self, value: unicode) -> None: ...

    @property
    def savedDomainFile(self) -> ghidra.framework.model.DomainFile: ...