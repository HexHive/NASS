import ghidra.feature.fid.hash
import ghidra.program.model.listing
import java.lang


class MessageDigestFidHasher(object, ghidra.feature.fid.hash.FidHasher):




    def __init__(self, __a0: ghidra.feature.fid.hash.FunctionExtentGenerator, __a1: int, __a2: generic.hash.MessageDigestFactory, __a3: java.util.Collection): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hash(self, __a0: ghidra.program.model.listing.Function) -> ghidra.feature.fid.hash.FidHashQuad: ...

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

