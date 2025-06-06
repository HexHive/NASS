from typing import List
import ghidra.program.model.address
import java.lang


class DefaultAddressFactory(object, ghidra.program.model.address.AddressFactory):
    """
    Keeps track of all the Address spaces in the program and provides
     methods for parsing address strings.
    """





    @overload
    def __init__(self, addrSpaces: List[ghidra.program.model.address.AddressSpace]):
        """
        Constructs a new DefaultAddressFactory.  The default space is assumed to be the first space
         in the array.
        @param addrSpaces array of address spaces for the Program
        """
        ...

    @overload
    def __init__(self, addrSpaces: List[ghidra.program.model.address.AddressSpace], defaultSpace: ghidra.program.model.address.AddressSpace):
        """
        Constructs a new DefaultAddressFactory with the given spaces and default space.
        @param addrSpaces the set of addressSpaces to manage
        @param defaultSpace the space to use as the default space. The default space should
         be one of the spaces provided in the addrSpaces array.
        """
        ...



    def equals(self, o: object) -> bool: ...

    @overload
    def getAddress(self, addrString: unicode) -> ghidra.program.model.address.Address:
        """
        @see ghidra.program.model.address.AddressFactory#getAddress(java.lang.String)
        """
        ...

    @overload
    def getAddress(self, spaceID: int, offset: long) -> ghidra.program.model.address.Address: ...

    @overload
    def getAddressSet(self) -> ghidra.program.model.address.AddressSet: ...

    @overload
    def getAddressSet(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressSet: ...

    @overload
    def getAddressSpace(self, spaceID: int) -> ghidra.program.model.address.AddressSpace: ...

    @overload
    def getAddressSpace(self, name: unicode) -> ghidra.program.model.address.AddressSpace: ...

    def getAddressSpaces(self) -> List[ghidra.program.model.address.AddressSpace]: ...

    def getAllAddressSpaces(self) -> List[ghidra.program.model.address.AddressSpace]: ...

    @overload
    def getAllAddresses(self, addrString: unicode) -> List[ghidra.program.model.address.Address]: ...

    @overload
    def getAllAddresses(self, addrString: unicode, caseSensitive: bool) -> List[ghidra.program.model.address.Address]: ...

    def getClass(self) -> java.lang.Class: ...

    def getConstantAddress(self, offset: long) -> ghidra.program.model.address.Address: ...

    def getConstantSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def getDefaultAddressSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def getIndex(self, addr: ghidra.program.model.address.Address) -> long: ...

    def getNumAddressSpaces(self) -> int: ...

    def getPhysicalSpace(self, space: ghidra.program.model.address.AddressSpace) -> ghidra.program.model.address.AddressSpace: ...

    def getPhysicalSpaces(self) -> List[ghidra.program.model.address.AddressSpace]: ...

    def getRegisterSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def getStackSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def getUniqueSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def hasMultipleMemorySpaces(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isValidAddress(self, addr: ghidra.program.model.address.Address) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def oldGetAddressFromLong(self, value: long) -> ghidra.program.model.address.Address: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet: ...

    @property
    def addressSpaces(self) -> List[ghidra.program.model.address.AddressSpace]: ...

    @property
    def allAddressSpaces(self) -> List[ghidra.program.model.address.AddressSpace]: ...

    @property
    def constantSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def defaultAddressSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def numAddressSpaces(self) -> int: ...

    @property
    def physicalSpaces(self) -> List[ghidra.program.model.address.AddressSpace]: ...

    @property
    def registerSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def stackSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def uniqueSpace(self) -> ghidra.program.model.address.AddressSpace: ...