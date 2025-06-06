from typing import List
import ghidra.feature.vt.api.markuptype
import java.lang


class VTMarkupTypeFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getID(__a0: ghidra.feature.vt.api.markuptype.VTMarkupType) -> int: ...

    @staticmethod
    def getMarkupType(__a0: int) -> ghidra.feature.vt.api.markuptype.VTMarkupType: ...

    @staticmethod
    def getMarkupTypes() -> List[object]: ...

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

