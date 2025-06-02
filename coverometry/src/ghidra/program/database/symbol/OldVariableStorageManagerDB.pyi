import ghidra.program.model.address
import java.lang


class OldVariableStorageManagerDB(object):




    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a read-only variable storage manager for the old record format
         utilized by the VariableStorage table (NOTE: old table name does not have
         a space in the name).  This adapter is intended for use during upgrades
         only.
        @param handle the database handle.
        @param addrMap the address map
        @param monitor the task monitor.
        @throws IOException if a database error occurs.
        @throws CancelledException if the user cancels the upgrade.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getStorageAddress(self, variableAddr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

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

