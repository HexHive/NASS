import ghidra.program.database.map
import ghidra.program.model.address
import ghidra.program.model.util
import java.lang


class PropertyMapDB(object, ghidra.program.model.util.PropertyMap):
    """
    Abstract class which defines a map containing properties over a set of addresses.
     The map is stored within a database table.
    """









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

    def get(self, __a0: ghidra.program.model.address.Address) -> object: ...

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

    @property
    def cacheSize(self) -> None: ...  # No getter available.

    @cacheSize.setter
    def cacheSize(self, value: int) -> None: ...

    @property
    def firstPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def lastPropertyAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def name(self) -> unicode: ...

    @property
    def propertyIterator(self) -> ghidra.program.model.address.AddressIterator: ...

    @property
    def size(self) -> int: ...

    @property
    def valueClass(self) -> java.lang.Class: ...