import db
import ghidra.program.database.module
import java.lang


class ParentChildDBAdapterV0(ghidra.program.database.module.ParentChildDBAdapter):




    def __init__(self, handle: db.DBHandle, create: bool, treeID: long):
        """
        Gets a version 0 adapter for the program tree parent/child database table.
        @param handle handle to the database containing the table.
        @param create true if this constructor should create the table.
        @param treeID associated program tree ID
        @throws VersionException if the the table's version does not match the expected version
         for this adapter.
        @throws IOException if database IO error occurs
        """
        ...



    def addParentChildRecord(self, moduleID: long, childID: long) -> db.DBRecord: ...

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

