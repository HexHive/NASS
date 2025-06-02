import ghidra.app.plugin.assembler.sleigh.grammars
import ghidra.app.plugin.assembler.sleigh.symbol
import java.lang


class AssemblyExtendedProduction(ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyProduction):
    """
    Defines a production of an "extended" grammar
    """





    def __init__(self, lhs: ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal, rhs: ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential, finalState: int, ancestor: ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction):
        """
        Construct an extended production based on the given ancestor
        @param lhs the extended left-hand side
        @param rhs the extended right-hand side
        @param finalState the end state of the final symbol of the RHS
        @param ancestor the original production from which this extended production is derived
        """
        ...



    @overload
    def compareTo(self, that: ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyProduction) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, that: object) -> bool: ...

    def getAncestor(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction:
        """
        Get the original production from which this production was derived
        @return the original production
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getFinalState(self) -> int:
        """
        Get the final state of this production
        @return the end state of the last symbol of the RHS
        """
        ...

    def getIndex(self) -> int:
        """
        Get the index of the production
 
         <p>
         Instead of using deep comparison, the index is often used as the identity of the production
         within a grammar.
        @return the index
        """
        ...

    def getLHS(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal: ...

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

    @property
    def LHS(self) -> ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal: ...

    @property
    def ancestor(self) -> ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction: ...

    @property
    def finalState(self) -> int: ...