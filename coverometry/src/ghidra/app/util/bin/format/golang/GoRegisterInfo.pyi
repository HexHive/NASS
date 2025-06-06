from typing import List
import ghidra.program.model.data
import ghidra.program.model.lang
import java.lang


class GoRegisterInfo(object):
    """
    Immutable information about registers, alignment sizes, etc needed to allocate storage
     for parameters during a function call.
 
    """









    def equals(self, __a0: object) -> bool: ...

    def getAlignmentForType(self, dt: ghidra.program.model.data.DataType) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getCurrentGoroutineRegister(self) -> ghidra.program.model.lang.Register: ...

    def getFloatRegisters(self) -> List[ghidra.program.model.lang.Register]: ...

    def getIntRegisterSize(self) -> int: ...

    def getIntRegisters(self) -> List[ghidra.program.model.lang.Register]: ...

    def getMaxAlign(self) -> int: ...

    def getStackInitialOffset(self) -> int: ...

    def getZeroRegister(self) -> ghidra.program.model.lang.Register: ...

    def hashCode(self) -> int: ...

    def isZeroRegisterIsBuiltin(self) -> bool: ...

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
    def currentGoroutineRegister(self) -> ghidra.program.model.lang.Register: ...

    @property
    def floatRegisters(self) -> List[object]: ...

    @property
    def intRegisterSize(self) -> int: ...

    @property
    def intRegisters(self) -> List[object]: ...

    @property
    def maxAlign(self) -> int: ...

    @property
    def stackInitialOffset(self) -> int: ...

    @property
    def zeroRegister(self) -> ghidra.program.model.lang.Register: ...

    @property
    def zeroRegisterIsBuiltin(self) -> bool: ...