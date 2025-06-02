import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator
import java.lang
import java.util.stream


class AssemblyNopStateGenerator(ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator):
    """
    The generator of AssemblyOperandState for a hidden value operand
 
 
     In short, this does nothing, except to hold the place of the operand for diagnostics. Likely, the
     "hidden" operand appears in the defining expression of a temporary symbol used in the print
     pieces.
    """





    def __init__(self, resolver: ghidra.app.plugin.assembler.sleigh.sem.AssemblyTreeResolver, opSym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol, fromLeft: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns):
        """
        Construct the hidden value operand state generator
        @param resolver the resolver
        @param opSym the operand symbol
        @param fromLeft the accumulated patterns from the left sibling or parent
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def generate(self, gc: ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator.GeneratorContext) -> java.util.stream.Stream: ...

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

