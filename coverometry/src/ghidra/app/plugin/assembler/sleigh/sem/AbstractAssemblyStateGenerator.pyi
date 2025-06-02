import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator
import java.lang
import java.util.stream


class AbstractAssemblyStateGenerator(object):
    """
    Base class for generating prototype nodes ("states") from a parse tree node
    """





    def __init__(self, __a0: ghidra.app.plugin.assembler.sleigh.sem.AssemblyTreeResolver, __a1: ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode, __a2: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns): ...



    def equals(self, __a0: object) -> bool: ...

    def generate(self, gc: ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyStateGenerator.GeneratorContext) -> java.util.stream.Stream:
        """
        Generate states
        @param gc the generator context for this node
        @return the stream of prototypes, each including accumulated patterns
        """
        ...

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

