import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator
import java.lang
import java.util.stream


class AssemblyHiddenConstructStateGenerator(ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructStateGenerator):
    """
    The generator of AssemblyConstructState for a hidden sub-table operand
 
 
     In short, this exhausts all possible constructors in the given sub-table. For well-designed
     languages, such exhaustion produces a very small set of possibilities. In general, hidden
     sub-table operands are a bad idea.
    """





    def __init__(self, resolver: ghidra.app.plugin.assembler.sleigh.sem.AssemblyTreeResolver, subtableSym: ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol, fromLeft: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns):
        """
        Construct the hidden sub-table operand state generator
        @param resolver the resolver
        @param subtableSym
        @param fromLeft the accumulated patterns from the left sibling or the parent
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

