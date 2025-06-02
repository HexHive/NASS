import ghidra.program.model.data.ISF
import java.lang


class IsfWinOS(object, ghidra.program.model.data.ISF.IsfObject):
    pdb: ghidra.program.model.data.ISF.IsfWinPDB
    pe: ghidra.program.model.data.ISF.IsfWinPE



    def __init__(self, __a0: java.util.Map): ...



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

