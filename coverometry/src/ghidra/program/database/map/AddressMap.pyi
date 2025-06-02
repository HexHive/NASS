from typing import List
import ghidra.program.database.map
import ghidra.program.model.address
import java.lang


class AddressMap(object):
    """
    Address map interface add methods need by the program database implementation to manage its address map.
     NOTE: Objects implementing this interface are not intended for use outside of the
     ghidra.program.database packages.
    """

    INVALID_ADDRESS_KEY: long = -0x1L







    def decodeAddress(self, value: long) -> ghidra.program.model.address.Address:
        """
        Returns the address that was used to generate the given long key. (If the image base was
         moved, then a different address is returned unless the value was encoded using the
         "absoluteEncoding" method.  If the program's default address space is segmented (i.e., SegmentedAddressSpace).
         the address returned will be always be normalized to defined segmented memory blocks if possible.
        @param value the long value to convert to an address.
        @return address decoded from long
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def findKeyRange(self, __a0: List[object], __a1: ghidra.program.model.address.Address) -> int: ...

    def getAbsoluteEncoding(self, addr: ghidra.program.model.address.Address, create: bool) -> long:
        """
        Get the database key associated with the given absolute address.
         This key uniquely identifies an absolute location within the program.
         If the requested key does not exist and create is false, INVALID_ADDRESS_KEY
         will be returned.  Note that nothing should ever be stored using the returned key unless
         create is true.
        @param addr the address for which to get a database key.
        @param create true if a new key may be generated
        @return the database key for the given address or INVALID_ADDRESS_KEY if 
         create is false and one does not exist for the specified addr.
        """
        ...

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Returns the address factory associated with this map.
         Null may be returned if map not associated with a specific address factory.
        @return associated {@link AddressFactory} or null
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getImageBase(self) -> ghidra.program.model.address.Address:
        """
        Returns the current image base setting.
        """
        ...

    def getKey(self, addr: ghidra.program.model.address.Address, create: bool) -> long:
        """
        Get the database key associated with the given relative address.
         This key uniquely identifies a relative location within the program.
         If the program's image base is moved to another address, this key will map to a new
         address that is the same distance to the new base as the old address was to the old base.
         If the requested key does not exist and create is false, INVALID_ADDRESS_KEY
         will be returned.  Note that nothing should ever be stored using the returned key unless
         create is true.
        @param addr the address for which to get a database key.
        @param create true if a new key may be generated
        @return the database key for the given address or INVALID_ADDRESS_KEY if 
         create is false and one does not exist for the specified addr.
        """
        ...

    @overload
    def getKeyRanges(self, set: ghidra.program.model.address.AddressSetView, create: bool) -> List[ghidra.program.model.address.KeyRange]:
        """
        Generates a properly ordered list of database key ranges for a
         a specified address set.  If absolute encodings are requested, 
         only memory addresses will be included.
        @param set address set or null for all addresses.  May not be null if <code>create</code> is true.
        @param create true if a new keys may be generated, otherwise returned 
         key-ranges will be limited to those already defined.
        @return "sorted" list of KeyRange objects
        """
        ...

    @overload
    def getKeyRanges(self, set: ghidra.program.model.address.AddressSetView, absolute: bool, create: bool) -> List[ghidra.program.model.address.KeyRange]:
        """
        Generates a properly ordered list of database key ranges for a
         a specified address set.  If absolute encodings are requested, 
         only memory addresses will be included.
        @param set address set or null for all addresses.  May not be null if <code>create</code> is true.
        @param absolute if true, absolute key encodings are returned, otherwise 
         standard/relocatable address key encodings are returned.
        @param create true if a new keys may be generated, otherwise returned 
         key-ranges will be limited to those already defined.
        @return "sorted" list of KeyRange objects
        """
        ...

    @overload
    def getKeyRanges(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, create: bool) -> List[ghidra.program.model.address.KeyRange]:
        """
        Generates a properly ordered list of database key ranges for a
         a specified address range.  If absolute encodings are requested, 
         only memory addresses will be included.  Returned key ranges are 
         generally intended for read-only operations since new keys will 
         never be generated.  The returned key ranges will correspond 
         to those key ranges which have previously been created within 
         the specified address range and may represent a much smaller subset 
         of addresses within the specified range. 
         NOTE: if the create parameter is true, the given range must not extend in the upper 32 bits 
         by more than 1 segment. For example, range(0x0000000000000000 - 0x0000000100000000) 
         is acceptable, but the range (0x0000000000000000 - 0x0000000200000000) is not because the
         upper 32 bits differ by 2.
        @param start the start address of the range
        @param end maximum address of range
        @param create true if a new keys may be generated, otherwise returned 
         key-ranges will be limited to those already defined. And if true, the range will be limited
         to a size of 2^32 so that at most it creates two new address bases
        @return "sorted" list of KeyRange objects
        @throws UnsupportedOperationException if the given range is so large that the upper 32 bit
         segments differ by more than 1.
        """
        ...

    @overload
    def getKeyRanges(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, absolute: bool, create: bool) -> List[ghidra.program.model.address.KeyRange]:
        """
        Generates a properly ordered list of database key ranges for a
         a specified address range.  If absolute encodings are requested, 
         only memory addresses will be included.
        @param start minimum address of range
        @param end maximum address of range
        @param absolute if true, absolute key encodings are returned, otherwise 
         standard/relocatable address key encodings are returned.
        @param create true if a new keys may be generated, otherwise returned 
         key-ranges will be limited to those already defined.
        @return "sorted" list of KeyRange objects
        """
        ...

    def getOldAddressMap(self) -> ghidra.program.database.map.AddressMap:
        """
        Returns an address map capable of decoding old address encodings.
        """
        ...

    def hashCode(self) -> int: ...

    def isUpgraded(self) -> bool:
        """
        Returns true if this address map has been upgraded.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory: ...

    @property
    def imageBase(self) -> ghidra.program.model.address.Address: ...

    @property
    def oldAddressMap(self) -> ghidra.program.database.map.AddressMap: ...

    @property
    def upgraded(self) -> bool: ...