import ghidra.app.plugin.assembler.sleigh.grammars
import java.lang


class AssemblyProduction(ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyProduction):
    """
    Defines a production for parsing mnemonic assembly
    """





    def __init__(self, lhs: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal, rhs: ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential): ...



    @overload
    def compareTo(self, that: ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyProduction) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, that: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getIndex(self) -> int:
        """
        Get the index of the production
 
         <p>
         Instead of using deep comparison, the index is often used as the identity of the production
         within a grammar.
        @return the index
        """
        ...

    def getLHS(self) -> NT:
        """
        Get the left-hand side
        @return the LHS
        """
        ...

    def getName(self) -> unicode:
        """
        Get the "name" of this production
 
         <p>
         This is mostly just notional and for debugging. The name is taken as the name of the LHS.
        @return the name of the LHS
        """
        ...

    def getRHS(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential:
        """
        Get the right-hand side
        @return the RHS
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

