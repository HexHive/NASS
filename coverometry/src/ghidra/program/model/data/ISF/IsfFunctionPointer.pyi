import ghidra.program.model.data.ISF
import java.lang


class IsfFunctionPointer(object, ghidra.program.model.data.ISF.IsfObject):
    kind: unicode
    subtype: ghidra.program.model.data.ISF.IsfObject



    def __init__(self, __a0: ghidra.program.model.data.FunctionDefinition, __a1: ghidra.program.model.data.DataType): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

