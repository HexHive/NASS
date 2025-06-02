from typing import List
import ghidra.app.plugin.assembler
import ghidra.app.plugin.assembler.sleigh.parse
import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang
import java.util


class SleighAssembler(object, ghidra.app.plugin.assembler.Assembler):
    """
    An Assembler for a SleighLanguage.
 
 
     For documentation on how the SLEIGH assembler works, see SleighAssemblerBuilder. To use
     the assembler, please use Assemblers#getAssembler(Program) or similar.
    """









    def assemble(self, at: ghidra.program.model.address.Address, assembly: List[unicode]) -> ghidra.program.model.listing.InstructionIterator: ...

    @overload
    def assembleLine(self, at: ghidra.program.model.address.Address, line: unicode) -> List[int]: ...

    @overload
    def assembleLine(self, at: ghidra.program.model.address.Address, line: unicode, ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> List[int]: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getContextAt(self, addr: ghidra.program.model.address.Address) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parseLine(self, line: unicode) -> java.util.Collection: ...

    @overload
    def patchProgram(self, insbytes: List[int], at: ghidra.program.model.address.Address) -> ghidra.program.model.listing.InstructionIterator: ...

    @overload
    def patchProgram(self, res: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, at: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction: ...

    @overload
    def resolveLine(self, at: ghidra.program.model.address.Address, line: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults: ...

    @overload
    def resolveLine(self, at: ghidra.program.model.address.Address, line: unicode, ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults: ...

    @overload
    def resolveTree(self, parse: ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult, at: ghidra.program.model.address.Address) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults: ...

    @overload
    def resolveTree(self, parse: ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult, at: ghidra.program.model.address.Address, ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

