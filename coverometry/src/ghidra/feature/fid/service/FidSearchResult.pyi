import java.lang


class FidSearchResult(object):
    function: ghidra.program.model.listing.Function
    hashQuad: ghidra.feature.fid.hash.FidHashQuad
    matches: List[object]



    def __init__(self, __a0: ghidra.program.model.listing.Function, __a1: ghidra.feature.fid.hash.FidHashQuad, __a2: List[object]): ...



    def equals(self, __a0: object) -> bool: ...

    def filterBySymbolPrefix(self, __a0: unicode) -> None: ...

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

