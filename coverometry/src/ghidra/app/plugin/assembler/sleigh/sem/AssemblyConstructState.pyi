import ghidra.app.plugin.assembler.sleigh.sem
import java.lang


class AssemblyConstructState(ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyState):
    """
    The state corresponding to a sub-table operand
 
 
     This is roughly analogous to ConstructState, but for assembly. It records the assembly
     semantic, i.e., SLEIGH constructor, and the child states, one for each operand in the
     constructor. It's implementation of #resolve(AssemblyResolvedPatterns, Collection)
     encapsulates, perhaps the very kernel of, machine-code generation. Operands can have there own
     complexity, but most of the core machine-code concepts of SLEIGH are handled by constructors.
    """





    def __init__(self, __a0: ghidra.app.plugin.assembler.sleigh.sem.AssemblyTreeResolver, __a1: List[object], __a2: int, __a3: ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic, __a4: List[object]): ...



    def computeHash(self) -> int: ...

    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLength(self) -> int:
        """
        Get the length in bytes of the operand represented by this node
        @return the length
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

