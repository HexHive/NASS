import ghidra.program.model.data
import ghidra.program.model.lang
import java.lang


class DynamicRegisterChangeListener(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def updateRegisterDataType(self, __a0: ghidra.program.model.lang.Register, __a1: ghidra.program.model.data.DataType) -> None: ...

    def updateRegisterValue(self, __a0: ghidra.program.model.lang.RegisterValue) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

