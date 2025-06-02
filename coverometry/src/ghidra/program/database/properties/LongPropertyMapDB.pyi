import ghidra.program.database.map
import ghidra.program.database.properties
import ghidra.program.model.address
import ghidra.program.model.util
import java.lang


class LongPropertyMapDB(ghidra.program.database.properties.PropertyMapDB, ghidra.program.model.util.LongPropertyMap):
    """
    Property manager that deals with properties that are of
     long type and stored with a database table.
    """





    def __init__(self, dbHandle: db.DBHandle, openMode: int, errHandler: db.util.ErrorHandler, changeMgr: ghidra.program.util.ChangeManager, addrMap: ghidra.program.database.map.AddressMap, name: unicode, monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a long property map.
        @param dbHandle database handle.
        @param openMode the mode that the program was openned in.
        @param errHandler database error handler.
        @param changeMgr change manager for event notification
        @param addrMap address map.
        @param name property name.
        @param monitor progress monitor that is only used when upgrading
        @throws VersionException if the database version is not the expected version.
        @throws CancelledException if the user cancels the upgrade operation.
        @throws IOException if a database io error occurs.
        """
        ...



    @overload
    def add(self, addr: ghidra.program.model.address.Address, value: long) -> None: ...

    @overload
    def add(self, __a0: ghidra.program.model.address.Address, __a1: object) -> None: ...

    def delete(self) -> None:
        """
        Delete this property map and all underlying tables.
         This method should be overidden if any table other than the 
         default propertyTable is used.
        @throws IOException if IO error occurs
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, addr: ghidra.program.model.address.Address) -> long: ...

    @overload
    def getAddressKeyIterator(self, start: ghidra.program.model.address.Address, before: bool) -> ghidra.program.database.map.AddressKeyIterator:
        """
        Get an iterator over the long address keys which contain a property value.
        @param start iterator starting position
        @param before true if the iterator should be positioned before the start address
        @return long address iterator.
        @throws IOException if IO error occurs
        """
        ...

    @overload
    def getAddressKeyIterator(self, set: ghidra.program.model.address.AddressSetView, atStart: bool) -> ghidra.program.database.map.AddressKeyIterator:
        """
        Get an iterator over the long address keys which contain a property value.
        @param set addresses over which to iterate (null indicates all defined memory regions)
        @param atStart true if the iterator should be positioned at the start
         of the range
        @return long address iterator.
        @throws IOException if IO error occurs
        """
        ...

    @overload
    def getAddressKeyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, atStart: bool) -> ghidra.program.database.map.AddressKeyIterator:
        """
        Get an iterator over the long address keys which contain a property value.
        @param start start of iterator address range
        @param end end of iterator address range
        @param atStart true if the iterator should be positioned at the start
         of the range
        @return long address iterator.
        @throws IOException if IO error occurs
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getFirstPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    def getLastPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    def getLong(self, addr: ghidra.program.model.address.Address) -> long: ...

    def getName(self) -> unicode: ...

    def getNextPropertyAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    def getPreviousPropertyAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    @overload
    def getPropertyIterator(self) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, asv: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, asv: ghidra.program.model.address.AddressSetView, forward: bool) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getPropertyIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator: ...

    def getSize(self) -> int: ...

    @staticmethod
    def getTableName(propertyName: unicode) -> unicode: ...

    def getValueClass(self) -> java.lang.Class: ...

    def hasProperty(self, addr: ghidra.program.model.address.Address) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def intersects(self, set: ghidra.program.model.address.AddressSetView) -> bool: ...

    @overload
    def intersects(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address) -> bool: ...

    def invalidateCache(self) -> None:
        """
        Invalidates the cache.
        """
        ...

    def moveRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, newStart: ghidra.program.model.address.Address) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self, addr: ghidra.program.model.address.Address) -> bool: ...

    def removeRange(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address) -> bool: ...

    def setCacheSize(self, size: int) -> None:
        """
        Adjust the size of the underlying read cache.
        @param size the size of the cache.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

