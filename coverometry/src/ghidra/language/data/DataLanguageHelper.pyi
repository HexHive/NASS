import ghidra.program.model.lang
import java.lang


class DataLanguageHelper(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getLanguage(__a0: ghidra.program.model.lang.LanguageService, __a1: int, __a2: bool) -> ghidra.program.model.lang.LanguageCompilerSpecPair: ...

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

