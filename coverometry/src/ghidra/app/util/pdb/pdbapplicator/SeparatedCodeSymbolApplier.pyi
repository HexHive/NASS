import ghidra.app.util.pdb.pdbapplicator
import java.lang


class SeparatedCodeSymbolApplier(ghidra.app.util.pdb.pdbapplicator.MsSymbolApplier):




    def __init__(self, __a0: ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator, __a1: ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator): ...



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

