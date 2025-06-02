import ghidra.app.plugin.assembler.sleigh.parse
import java.lang
import java.util


class AssemblyParseState(object, java.lang.Comparable):
    """
    A state in an LR(0) parsing machine
 
 
     Each item consists of a kernel and an implied closure. Only the kernel is necessary to define the
     item, but the whole closure must be considered when deriving new states. The kernel can be
     retrieved and mutated via #getKernel(), then the closure derived from it via
     #getClosure().
    """





    @overload
    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar):
        """
        Construct a new state associated with the given grammar
        @param grammar the grammar
        """
        ...

    @overload
    def __init__(self, grammar: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar, item: ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseStateItem):
        """
        Construct a new state associated with the given grammar, seeded with the given item
        @param grammar the grammar
        @param item an item in the state
        """
        ...



    @overload
    def compareTo(self, that: ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseState) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, that: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getClosure(self) -> java.util.Set:
        """
        Get the closure of this item, caching the result
        @return the closure
        """
        ...

    def getKernel(self) -> java.util.Set:
        """
        Get the (mutable) kernel for this state
        @return the kernel
        """
        ...

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
    def closure(self) -> java.util.Set: ...

    @property
    def kernel(self) -> java.util.Set: ...