from typing import List
import ghidra.program.model.address
import java.lang


class ProgramAddressFactory(ghidra.program.model.address.DefaultAddressFactory):




    def __init__(self, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec): ...



    def equals(self, o: object) -> bool: ...

    @overload
    def getAddress(self, addrString: unicode) -> ghidra.program.model.address.Address: ...

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
    def stackSpace(self) -> ghidra.program.model.address.AddressSpace: ...