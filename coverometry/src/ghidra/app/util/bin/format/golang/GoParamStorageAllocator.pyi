from typing import List
import ghidra.app.util.bin.format.golang
import ghidra.program.model.data
import ghidra.program.model.lang
import java.lang


class GoParamStorageAllocator(object):
    """
    Logic and helper for allocating storage for a function's parameters and return value.
 
     Not threadsafe.
    """





    def __init__(self, program: ghidra.program.model.listing.Program, goVersion: ghidra.app.util.bin.format.golang.GoVer):
        """
        Creates a new golang function call storage allocator for the specified Ghidra Language.
         <p>
         See {@link GoRegisterInfoManager#getRegisterInfoForLang(Language, GoVer)}
        @param program {@link Program}
        @param goVersion version of go used to create the program
        """
        ...



    def alignStack(self) -> None: ...

    def alignStackFor(self, dt: ghidra.program.model.data.DataType) -> None: ...

    def clone(self) -> ghidra.app.util.bin.format.golang.GoParamStorageAllocator: ...

    def equals(self, __a0: object) -> bool: ...

    def getAbi0CallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    def getAbiInternalCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    def getArchDescription(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getRegistersFor(self, dt: ghidra.program.model.data.DataType) -> List[ghidra.program.model.lang.Register]:
        """
        Returns a list of {@link Register registers} that will successfully store the specified
         data type, as well as marking those registers as used and unavailable.
        @param dt {@link DataType} to allocate register space for
        @return list of {@link Register registers}, possibly empty if the data type was zero-length,
         possibly null if the data type is not compatible with register storage
        """
        ...

    @overload
    def getRegistersFor(self, dt: ghidra.program.model.data.DataType, allowEndianFixups: bool) -> List[ghidra.program.model.lang.Register]:
        """
        Returns a list of {@link Register registers} that will successfully store the specified
         data type, as well as marking those registers as used and unavailable.
        @param dt {@link DataType} to allocate register space for
        @param allowEndianFixups boolean flag, if true the result (if it contains more than a single
         location) will automatically be adjusted in little endian programs to match how storage
         varnodes are laid-out, if false the result will not be adjusted
        @return list of {@link Register registers}, possibly empty if the data type was zero-length,
         possibly null if the data type is not compatible with register storage
        """
        ...

    def getStackAllocation(self, dt: ghidra.program.model.data.DataType) -> long:
        """
        Returns the stack offset that should be used to store the data type on the stack, as well
         as marking that stack area as used and unavailable.
        @param dt {@link DataType} to allocate stack space for
        @return offset in stack where the data item will be located
        """
        ...

    def getStackOffset(self) -> long: ...

    def hashCode(self) -> int: ...

    def isAbi0Mode(self) -> bool: ...

    def isBigEndian(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def resetRegAllocation(self) -> None: ...

    def setAbi0Mode(self) -> None: ...

    def setStackOffset(self, newStackOffset: long) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def abi0CallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def abi0Mode(self) -> bool: ...

    @property
    def abiInternalCallingConvention(self) -> ghidra.program.model.lang.PrototypeModel: ...

    @property
    def archDescription(self) -> unicode: ...

    @property
    def bigEndian(self) -> bool: ...

    @property
    def stackOffset(self) -> long: ...

    @stackOffset.setter
    def stackOffset(self, value: long) -> None: ...