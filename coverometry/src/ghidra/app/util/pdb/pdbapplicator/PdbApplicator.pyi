from typing import List
import ghidra.app.util.bin.format.pdb2.pdbreader
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class PdbApplicator(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLinkerModuleCompileSymbol(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol: ...

    def getLinkerPeCoffSectionSymbols(self) -> List[object]: ...

    def getMonitor(self) -> ghidra.util.task.TaskMonitor: ...

    def getOriginalImageBase(self) -> long: ...

    def getPdb(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

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

    @property
    def linkerModuleCompileSymbol(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol: ...

    @property
    def linkerPeCoffSectionSymbols(self) -> List[object]: ...

    @property
    def monitor(self) -> ghidra.util.task.TaskMonitor: ...

    @property
    def originalImageBase(self) -> long: ...

    @property
    def pdb(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...