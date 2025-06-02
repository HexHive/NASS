import ghidra.app.util.importer
import ghidra.program.model.listing
import java.lang


class DtbUtil(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isCorrectLoader(__a0: ghidra.program.model.listing.Program) -> bool: ...

    @staticmethod
    def isCorrectProcessor(__a0: ghidra.program.model.listing.Program, __a1: ghidra.app.util.importer.MessageLog) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

