import ghidra.program.database
import ghidra.program.model.data
import ghidra.util
import java.lang


class SourceArchiveDB(ghidra.program.database.DatabaseObject, ghidra.program.model.data.SourceArchive):




    def __init__(self, dtMgr: ghidra.program.database.data.DataTypeManagerDB, cache: ghidra.program.database.DBObjectCache, adapter: ghidra.program.database.data.SourceArchiveAdapter, record: db.DBRecord): ...



    def equals(self, __a0: object) -> bool: ...

    def getArchiveType(self) -> ghidra.program.model.data.ArchiveType:
        """
        Gets an indicator for the type of data type archive.
         (PROGRAM_TYPE, PROJECT_TYPE, FILE_TYPE)
        @return the type
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDomainFileID(self) -> unicode:
        """
        Gets the ID used to uniquely identify the domain file for the data type archive.
        @return the domain file identifier
        """
        ...

    def getKey(self) -> long:
        """
        Get the database key for this object.
        """
        ...

    def getLastSyncTime(self) -> long: ...

    def getName(self) -> unicode: ...

    def getSourceArchiveID(self) -> ghidra.util.UniversalID:
        """
        Gets the ID that the program has associated with the data type archive.
        @return the data type archive ID
        """
        ...

    def hashCode(self) -> int: ...

    def isDeleted(self, lock: ghidra.util.Lock) -> bool:
        """
        Returns true if this object has been deleted. Note: once an object has been deleted, it will
         never be "refreshed". For example, if an object is ever deleted and is resurrected via an
         "undo", you will have get a fresh instance of the object.
        @param lock object cache lock object
        @return true if this object has been deleted.
        """
        ...

    def isDirty(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setDirtyFlag(self, isDirty: bool) -> None: ...

    def setInvalid(self) -> None:
        """
        Invalidate this object. This does not necessarily mean that this object can never be used
         again. If the object can refresh itself, it may still be useable.
        """
        ...

    def setLastSyncTime(self, syncTime: long) -> None: ...

    def setName(self, newName: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def archiveType(self) -> ghidra.program.model.data.ArchiveType: ...

    @property
    def dirty(self) -> bool: ...

    @property
    def dirtyFlag(self) -> None: ...  # No getter available.

    @dirtyFlag.setter
    def dirtyFlag(self, value: bool) -> None: ...

    @property
    def domainFileID(self) -> unicode: ...

    @property
    def lastSyncTime(self) -> long: ...

    @lastSyncTime.setter
    def lastSyncTime(self, value: long) -> None: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def sourceArchiveID(self) -> ghidra.util.UniversalID: ...