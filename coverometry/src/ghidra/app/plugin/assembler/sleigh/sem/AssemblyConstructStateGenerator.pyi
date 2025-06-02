import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator
import java.lang
import java.util.stream


class AssemblyConstructStateGenerator(ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator):
    """
    The generator of AssemblyConstructState from AssemblyParseBranch
 
 
     In short, this handles the selection of each possible constructor for the production recorded by
     a given parse branch.
    """





    def __init__(self, resolver: ghidra.app.plugin.assembler.sleigh.sem.AssemblyTreeResolver, node: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch, fromLeft: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns):
        """
        Construct the instruction state generator or a sub-table operand state generator
        @param resolver the resolver
        @param node the node from which to generate states
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

