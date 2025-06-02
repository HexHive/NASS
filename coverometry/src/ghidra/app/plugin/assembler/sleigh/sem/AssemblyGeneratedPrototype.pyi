import java.lang


class AssemblyGeneratedPrototype(object):
    """
    A tree of generated assembly node states, paired with the resulting patterns
 
 
     This is used as the intermediate result when generating states, since the patterns must be
     propagated to each operand as generation proceeds. Usually, the patterns in the final output are
     discarded, and machine code generation proceeds using only the state tree.
    """





    def __init__(self, state: ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyState, patterns: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns): ...



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

