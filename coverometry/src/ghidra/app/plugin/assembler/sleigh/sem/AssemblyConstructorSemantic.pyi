from typing import Iterator
from typing import List
import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.pattern
import java.lang
import java.util
import java.util.stream


class AssemblyConstructorSemantic(object, java.lang.Comparable):
    """
    Describes a SLEIGH constructor semantic
 
 
     These are collected and associated with productions in the grammar based on the given
     constructor's print pieces.
    """





    def __init__(self, __a0: ghidra.app.plugin.processors.sleigh.Constructor, __a1: List[object]): ...



    @overload
    def addPattern(self, pat: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> None:
        """
        Record a pattern that would select the constructor
        @param pat the pattern
        """
        ...

    @overload
    def addPattern(self, pat: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern) -> None:
        """
        Record a pattern that would select the constructor
        @param pat the pattern
        """
        ...

    def applyContextChangesForward(self, vals: java.util.Map, fromLeft: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Apply just context transformations in the forward (disassembly) direction
 
         <p>
         Unlike the usual disassembly process, this method does not take into account any information
         from the instruction encoding. Any context bits that depend on it are set to unknown
         ({@code x}) in the output. This method is used to pre-compute a context transition graph in
         order to quickly resolve purely-recursive semantics on the root constructor table.
        @param fromLeft the state before context changes
        @return the state after context changes
        """
        ...

    def applyPatternsForward(self, shift: int, fromLeft: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> java.util.stream.Stream:
        """
        Apply just the instruction patterns in the forward (disassembly) direction
        @param shift the (right) shift in bytes to apply to the patterns before combining
        @param fromLeft the accumulated patterns from the left sibling or parent
        @return 
        """
        ...

    @overload
    def compareTo(self, that: ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getConstructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor:
        """
        Get the SLEIGH constructor
        @return the constructor
        """
        ...

    @overload
    def getLocation(self) -> unicode:
        """
        Render this constructor's source location for diagnostics
        @return the location
        """
        ...

    @overload
    @staticmethod
    def getLocation(cons: ghidra.app.plugin.processors.sleigh.Constructor) -> unicode:
        """
        Render the constructor's source location for diagnostics
        @param cons the constructor
        @return the location as {@code file:lineno}
        """
        ...

    def getOperandIndex(self, printpos: int) -> int:
        """
        Convert the index of a print piece to its associated operand index
        @param printpos position excluding whitespace and string tokens.
        @return the operand index
        """
        ...

    def getOperandIndexIterator(self) -> Iterator[int]:
        """
        Get an iterator over the operand indices
 
         <p>
         If this iterator is advanced for each non-terminal, while simultaneously iterating over the
         RHS of the associated production, then this will identify the corresponding operand index for
         each non-terminal
        @return the iterator
        """
        ...

    def getOperandIndices(self) -> List[int]:
        """
        Get the list of operand indices in print piece order
        @return the list
        """
        ...

    def getPatterns(self) -> java.util.Collection:
        """
        Get the associated encoding patterns for the constructor
        @return the patterns
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def solveContextChanges(self, res: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, vals: java.util.Map) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Solve this constructor's context changes
 
         <p>
         Each value in {@code opvals} must either be a numeric value, e.g., an index from a varnode
         list, or another {@link AssemblyResolvedPatterns} for a subconstructor operand.
 
         <p>
         It's helpful to think of the SLEIGH disassembly process here. Normally, once the appropriate
         constructor has been identified (by matching patterns), its context changes are applied, and
         then its operands parsed (possibly parsing subconstructor operands). Thus, {@code res} can be
         thought of as the intermediate result between applying context changes and parsing operands,
         except in reverse. The output of this method corresponds to the state before context changes
         were applied, i.e., immediately after selecting the constructor. Thus, in reverse, the
         context is solved immediately before applying the selected constructor patterns.
        @param res the combined resolution requirements derived from the subconstructors
        @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
        @return the resolution with context changes applied in reverse, or an error
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def constructor(self) -> ghidra.app.plugin.processors.sleigh.Constructor: ...

    @property
    def location(self) -> unicode: ...

    @property
    def operandIndexIterator(self) -> java.util.Iterator: ...

    @property
    def operandIndices(self) -> List[object]: ...

    @property
    def patterns(self) -> java.util.Collection: ...