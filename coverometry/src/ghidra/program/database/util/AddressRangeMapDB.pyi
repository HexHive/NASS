import db
import ghidra.program.model.address
import ghidra.util.task
import java.lang


class AddressRangeMapDB(object, db.DBListener):
    """
    AddressRangeMapDB provides a generic value range map backed by a database table.
     Values can be stored for ranges of addresses. When a value is stored for a range, it replaces
     any previous values for that range. It is kind of like painting. If you first paint a region
     red, but then later paint a region in the middle of the red region green, you end up with
     three regions - a green region surrounded by two red regions.
 
     This is implemented by storing records for each contiguous range with the same value.
 
     		The key is the encoded start address of the range.
     		The TO_COL column of the record stores the encoded end address of the range.
     		The VALUE_COL column of the record stores the value for the range.
 
 
     This implementation is complicated by several issues. 
 
     	   Addresses stored in Ghidra database records are encoded as long keys (see 
     		  AddressMap). 
     		  Encoded addresses do not necessarily encode to keys that have the same ordering. 
     	      Therefore, all comparisons must be done in address space and not in the encoded space.
     		  Also, record iterators must use the AddressKeyRecordIterator which will return
     		  records in address order versus encoded key order.
         The default space's image base can be changed after records have been created. This can
            cause the address ranges represented by a record to wrap around. For example, suppose
            the image base is 0 and you paint a range from address 0 to 0x20, which say maps to
            keys 0 and 20, respectively. Now suppose the image base changes to 0xfffffffe, which 
            means key 0 maps to address 0xfffffffe and key 0x20 maps to address 0x1e,(the addresses
            have been effectively shifted down by 2). So now the stored record has a start key of
            0 and an end key of 0x20 which now maps to start address of 0xfffffffe and an end 
            address of 0x1e. For our purposes, it is important that we don't just flip the start
            and end address which be a very large range instead of a small range. Instead, we need 
            to interpret that as 2 ranges (0xfffffffe - 0xffffffff) and (0 - 0x1e). So all methods
            in this class have be coded to handle this special case. To simplify the painting
            logic, any wrapping record will first be split into two records before painting. However
            we can only do this during a write operation (when we can make changes). Since the getter
            methods and iterators cannot modify the database, they have to deal with wrapping
            records on the fly.
    """

    RANGE_MAP_TABLE_PREFIX: unicode = u'Range Map - '



    def __init__(self, dbHandle: db.DBHandle, addressMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock, name: unicode, errHandler: db.util.ErrorHandler, valueField: db.Field, indexed: bool):
        """
        Construct a generic range map
        @param dbHandle database handle
        @param addressMap the address map
        @param lock the program lock
        @param name map name used in naming the underlying database table
         This name must be unique across all range maps
        @param errHandler database error handler
        @param valueField specifies the type for the values stored in this map
        @param indexed if true, values will be indexed allowing use of the 
         getValueRangeIterator method
        """
        ...



    def clearRange(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address) -> None:
        """
        Remove values from the given range.
        @param startAddr the start address.
        @param endAddr the end address.
        """
        ...

    def dbClosed(self, dbh: db.DBHandle) -> None: ...

    def dbRestored(self, dbh: db.DBHandle) -> None: ...

    def dispose(self) -> None:
        """
        Deletes the database table used to store this range map.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def exists(dbHandle: db.DBHandle, name: unicode) -> bool:
        """
        Tests if an AddressRangeMap table exists with the given name
        @param dbHandle the database handle
        @param name the name to test for
        @return true if the a table exists for the given name
        """
        ...

    def getAddressRangeContaining(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Returns the bounding address range for the given address where all addresses in that
         range have the same value (this also works for now value. i.e finding a gap)
        @param address the address to find a range for
        @return an address range that contains the given address and has all the same value
        """
        ...

    @overload
    def getAddressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an address range iterator over all ranges in the map where a value has been set
        @return AddressRangeIterator that iterates over all occupied ranges in the map
        """
        ...

    @overload
    def getAddressRanges(self, startAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an address range iterator over all ranges in the map where a value has been set
         starting with the given address
        @param startAddress The address at which to start iterating ranges
        @return AddressRangeIterator that iterates over all occupied ranges in the map from the
         given start address
        """
        ...

    @overload
    def getAddressRanges(self, startAddress: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an address range iterator over all ranges in the map where a value has been set
         starting with the given address and ending with the given end address
        @param startAddress the address at which to start iterating ranges
        @param endAddr the address at which to end the iterator
        @return AddressRangeIterator that iterates over all occupied ranges in the map from the
         given start address
        """
        ...

    @overload
    def getAddressSet(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns set of addresses where a values has been set
        @return set of addresses where a values has been set
        """
        ...

    @overload
    def getAddressSet(self, value: db.Field) -> ghidra.program.model.address.AddressSet:
        """
        Returns set of addresses where the given value has been set
        @param value the value to search for
        @return set of addresses where the given value has been set
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getRecordCount(self) -> int:
        """
        Returns the number of records contained within this map.
         NOTE: This number will be greater or equal to the number of
         address ranges contained within the map.
        @return record count
        """
        ...

    def getValue(self, address: ghidra.program.model.address.Address) -> db.Field:
        """
        Returns the value associated with the given address
        @param address the address of the value
        @return value or null no value exists
        """
        ...

    def hashCode(self) -> int: ...

    def invalidate(self) -> None:
        """
        Notification that that something may have changed (undo/redo/image base change) and we need
         to invalidate our cache and possibly have a wrapping record again.
        """
        ...

    def isEmpty(self) -> bool:
        """
        Returns true if this map is empty
        @return true if this map is empty
        """
        ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: long, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Move all values within an address range to a new range.
        @param fromAddr the first address of the range to be moved.
        @param toAddr the address where to the range is to be moved.
        @param length the number of addresses to move.
        @param monitor the task monitor.
        @throws CancelledException if the user canceled the operation via the task monitor.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def paintRange(self, startAddress: ghidra.program.model.address.Address, endAddress: ghidra.program.model.address.Address, value: db.Field) -> None:
        """
        Associates the given value with every address from start to end (inclusive)
         Any previous associates are overwritten.
        @param startAddress the start address.
        @param endAddress the end address.
        @param value value to be painted, or null for value removal.
        @throws IllegalArgumentException if the start and end addresses are not in the same
         address space
        @throws IllegalArgumentException if the end address is greater then the start address
        """
        ...

    def setName(self, newName: unicode) -> bool:
        """
        Set the name associated with this range map
        @param newName the new name for this range map
        @return true if successful, else false
        @throws DuplicateNameException if there is already range map with that name
        """
        ...

    def tableAdded(self, dbh: db.DBHandle, table: db.Table) -> None: ...

    def tableDeleted(self, dbh: db.DBHandle, table: db.Table) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressRanges(self) -> ghidra.program.model.address.AddressRangeIterator: ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet: ...

    @property
    def empty(self) -> bool: ...

    @property
    def name(self) -> None: ...  # No getter available.

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def recordCount(self) -> int: ...