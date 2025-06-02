import db
import ghidra.program.database.symbol
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.task
import java.lang


class VariableStorageManagerDB(object, ghidra.program.database.symbol.VariableStorageManager):




    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: int, errorHandler: db.util.ErrorHandler, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a new variable manager.
        @param handle the database handle.
        @param addrMap the address map (required for legacy adpter use only)
        @param openMode the open mode
        @param errorHandler database error handler
        @param lock the program synchronization lock
        @param monitor the task monitor.
        @throws IOException if a database error occurs.
        @throws VersionException if the table version is different from this adapter.
        @throws IOException if an IO error occurs
        @throws CancelledException if the user cancels the upgrade.
        """
        ...



    @staticmethod
    def delete(dbHandle: db.DBHandle) -> None:
        """
        Delete the DB table which correspnds to this variable storage implementation
        @param dbHandle database handle
        @throws IOException if an IO error occurs
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def exists(dbHandle: db.DBHandle) -> bool:
        """
        Determine if the variable storage manager table already exists
        @param dbHandle database handle
        @return true if storage table exists
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getVariableStorageAddress(self, storage: ghidra.program.model.listing.VariableStorage, create: bool) -> ghidra.program.model.address.Address:
        """
        Get a variable address for the given storage specification.
         NOTE: The program architecture and error handler must be set appropriately prior to 
         invocation of this method (see {@link #setProgramArchitecture(ProgramArchitecture)}.
        @param storage variable storage specification
        @param create if true a new variable address will be allocated if needed
        @return variable address which corresponds to the storage specification or null if not found
         and create is false.
        @throws IOException if an IO error occurs
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setLanguage(self, translator: ghidra.program.util.LanguageTranslator, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Perform language translation.
         Following the invocation of this method it is important to ensure that the program 
         architecure is adjusted if neccessary.
         Update variable storage specifications to reflect address space and register mappings
        @param translator language translator to be used for mapping storage varnodes to new
         architecture.
        @param monitor task monitor
        @throws CancelledException if task is cancelled
        """
        ...

    def setProgramArchitecture(self, arch: ghidra.program.model.lang.ProgramArchitecture) -> None:
        """
        Set program architecture.
        @param arch program architecture
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
    def programArchitecture(self) -> None: ...  # No getter available.

    @programArchitecture.setter
    def programArchitecture(self, value: ghidra.program.model.lang.ProgramArchitecture) -> None: ...