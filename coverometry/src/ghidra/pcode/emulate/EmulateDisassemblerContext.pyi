from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import java.lang


class EmulateDisassemblerContext(object, ghidra.program.model.lang.DisassemblerContext):




    def __init__(self, __a0: ghidra.program.model.lang.Language, __a1: ghidra.program.model.lang.RegisterValue): ...



    def clearRegister(self, __a0: ghidra.program.model.lang.Register) -> None: ...

    @overload
    @staticmethod
    def dumpContextValue(__a0: ghidra.program.model.lang.RegisterValue, __a1: unicode) -> unicode: ...

    @overload
    @staticmethod
    def dumpContextValue(__a0: ghidra.program.model.lang.RegisterValue, __a1: unicode, __a2: java.lang.StringBuilder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getBaseContextRegister(self) -> ghidra.program.model.lang.Register: ...

    def getClass(self) -> java.lang.Class: ...

    def getCurrentContextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue: ...

    def getRegister(self, __a0: unicode) -> ghidra.program.model.lang.Register: ...

    def getRegisterValue(self, __a0: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue: ...

    def getRegisters(self) -> List[object]: ...

    def getValue(self, __a0: ghidra.program.model.lang.Register, __a1: bool) -> long: ...

    def hasValue(self, __a0: ghidra.program.model.lang.Register) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setCurrentAddress(self, __a0: ghidra.program.model.address.Address) -> None: ...

    @overload
    def setFutureRegisterValue(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.lang.RegisterValue) -> None: ...

    @overload
    def setFutureRegisterValue(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.lang.RegisterValue) -> None: ...

    def setRegisterValue(self, __a0: ghidra.program.model.lang.RegisterValue) -> None: ...

    def setValue(self, __a0: ghidra.program.model.lang.Register, __a1: long) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def baseContextRegister(self) -> ghidra.program.model.lang.Register: ...

    @property
    def currentAddress(self) -> None: ...  # No getter available.

    @currentAddress.setter
    def currentAddress(self, value: ghidra.program.model.address.Address) -> None: ...

    @property
    def currentContextRegisterValue(self) -> ghidra.program.model.lang.RegisterValue: ...

    @property
    def registerValue(self) -> None: ...  # No getter available.

    @registerValue.setter
    def registerValue(self, value: ghidra.program.model.lang.RegisterValue) -> None: ...

    @property
    def registers(self) -> List[object]: ...