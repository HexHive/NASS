from typing import List
import ghidra.app.plugin.assembler.sleigh.expr
import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.expression
import ghidra.app.plugin.processors.sleigh.pattern
import java.lang
import java.util


class AssemblyResolvedBackfill(ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution):
    """
    A AssemblyResolution indicating the need to solve an expression in the future
 
 
     Such records are collected within a AssemblyResolvedPatterns and then solved just before
     the final result(s) are assembled. This is typically required by instructions that refer to the
      symbol.
 
 
     NOTE: These are used internally. The user ought never to see these from the assembly API.
    """









    @staticmethod
    def backfill(exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, goal: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong, inslen: int, description: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedBackfill:
        """
        Build a backfill record to attach to a successful resolution result
        @param exp the expression depending on a missing symbol
        @param goal the desired value of the expression
        @param inslen the length of instruction portion expected in the future solution
        @param description a description of the backfill record
        @return the new record
        """
        ...

    @overload
    def compareTo(self, that: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    @staticmethod
    def contextOnly(ctx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock, description: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Build a context-only successful resolution result
        @param ctx the context pattern block
        @param description a description of the resolution
        @return the new resolution
        @see #resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List, AssemblyResolution)
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    @staticmethod
    def error(error: unicode, description: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError:
        """
        Build an error resolution record
        @param error a description of the error
        @param description a description of what the resolver was doing when the error occurred
        @return the new resolution
        """
        ...

    @overload
    @staticmethod
    def error(error: unicode, res: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Build an error resolution record, based on an intermediate SLEIGH constructor record
        @param error a description of the error
        @param res the constructor record that was being populated when the error ocurred
        @return the new error resolution
        """
        ...

    @overload
    @staticmethod
    def error(__a0: unicode, __a1: unicode, __a2: List[object], __a3: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError: ...

    @staticmethod
    def fromPattern(pat: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern, minLen: int, description: unicode, cons: ghidra.app.plugin.processors.sleigh.Constructor) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Build a successful resolution result from a SLEIGH constructor's patterns
        @param pat the constructor's pattern
        @param description a description of the resolution
        @return the new resolution
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getInstructionLength(self) -> int:
        """
        Get the expected length of the instruction portion of the future encoding
 
         This is used to make sure that operands following a to-be-determined encoding are placed
         properly. Even though the actual encoding cannot yet be determined, its length can.
        @return the total expected length (including the offset)
        """
        ...

    def hasChildren(self) -> bool:
        """
        Check if this record has children
 
         <p>
         If a subclass has another, possibly additional, notion of children that it would like to
         include in {@link #toString()}, it must override this method to return true when such
         children are present.
        @see #childrenToString(String)
        @return true if this record has children
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def instrOnly(ins: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock, description: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Build an instruction-only successful resolution result
        @param ins the instruction pattern block
        @param description a description of the resolution
        @return the new resolution
        @see #resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List, AssemblyResolution)
        """
        ...

    def isBackfill(self) -> bool: ...

    def isError(self) -> bool: ...

    @overload
    @staticmethod
    def nop(description: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Obtain a new "blank" resolved SLEIGH constructor record
        @param description a description of the resolution
        @return the new resolution
        """
        ...

    @overload
    @staticmethod
    def nop(__a0: unicode, __a1: List[object], __a2: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parent(self, description: unicode, opCount: int) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution: ...

    @staticmethod
    def resolved(__a0: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock, __a1: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock, __a2: unicode, __a3: ghidra.app.plugin.processors.sleigh.Constructor, __a4: List[object], __a5: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns: ...

    def shift(self, amt: int) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedBackfill: ...

    def solve(self, solver: ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver, vals: java.util.Map, cur: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Attempt (again) to solve the expression that generated this backfill record
 
         This will attempt to solve the same expression and goal again, using the same parameters as
         were given to the original attempt, except with additional defined symbols. Typically, the
         symbol that required backfill is {@code inst_next}. This method will not throw
         {@link NeedsBackfillException}, since that would imply the missing symbol(s) from the
         original attempt are still missing. Instead, the method returns an instance of
         {@link AssemblyResolvedError}.
        @param solver a solver, usually the same as the one from the original attempt.
        @param vals the defined symbols, usually the same, but with the missing symbol(s).
        @return the solution result
        """
        ...

    @overload
    def toString(self) -> unicode:
        """
        Describe this record including indented children, grandchildren, etc., each on its own line
        """
        ...

    @overload
    def toString(self, indent: unicode) -> unicode:
        """
        Used only by parents: get a multi-line description of this record, indented
        @param indent the current indentation
        @return the indented description
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def withRight(self, right: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedBackfill: ...

    def withoutRight(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Get this same resolution, but without any right siblings
        @return the resolution
        """
        ...

    @property
    def instructionLength(self) -> int: ...