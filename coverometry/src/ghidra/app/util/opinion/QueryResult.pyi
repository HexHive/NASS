import java.lang


class QueryResult(object):
    pair: ghidra.program.model.lang.LanguageCompilerSpecPair
    preferred: bool



    def __init__(self, pair: ghidra.program.model.lang.LanguageCompilerSpecPair, preferred: bool): ...



    def equals(self, obj: object) -> bool: ...

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

