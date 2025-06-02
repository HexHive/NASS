from typing import List
import ghidra.app.plugin.assembler.sleigh.expr
import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.expression
import ghidra.app.plugin.processors.sleigh.pattern
import java.lang
import java.util


class AssemblyResolvedPatterns(ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution):
    """
    A AssemblyResolution indicating successful application of a constructor
 
 
     This is almost analogous to ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern, in that is joins an instruction AssemblyPatternBlock with a
     corresponding context AssemblyPatternBlock. However, this object is mutable, and it
     collects backfill records, as well as forbidden patterns.
 
 
     When the applied constructor is from the "instruction" subtable, this represents a fully-
     constructed instruction with required context. All backfill records ought to be resolved and
     applied before the final result is given to the user, i.e., passed into the
     AssemblySelector. If at any time during the resolution or backfill process, the result
     becomes confined to one of the forbidden patterns, it must be dropped, since the encoding will
     actually invoke a more specific SLEIGH constructor.
    """









    @overload
    def backfill(self, solver: ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver, vals: java.util.Map) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Apply as many backfill records as possible
 
         <p>
         Each backfill record is resolved in turn, if the record cannot be resolved, it remains
         listed. If the record can be resolved, but it conflicts, an error record is returned. Each
         time a record is resolved and combined successfully, all remaining records are tried again.
         The result is the combined resolved backfills, with only the unresolved backfill records
         listed.
        @param solver the solver, usually the same as the original attempt to solve.
        @param vals the values.
        @return the result, or an error.
        """
        ...

    @overload
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

    def checkNotForbidden(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Check if the current encoding is forbidden by one of the attached patterns
 
         <p>
         The pattern becomes forbidden if this encoding's known bits are an overset of any forbidden
         pattern's known bits.
        @return false if the pattern is forbidden (and thus in error), true if permitted
        """
        ...

    @overload
    def combine(self, bf: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedBackfill) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Combine the given backfill record into this resolution
        @param bf the backfill record
        @return the result
        """
        ...

    @overload
    def combine(self, that: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Combine the encodings and backfills of the given resolution into this one
 
         <p>
         This combines corresponding pattern blocks (assuming they agree), collects backfill records,
         and collects forbidden patterns.
        @param that the other resolution
        @return the result if successful, or null
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

    def copyAppendDescription(self, append: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Duplicate this resolution, with additional description text appended
        @param append the text to append
        @return the duplicate NOTE: An additional separator {@code ": "} is inserted
        """
        ...

    def dumpConstructorTree(self) -> unicode:
        """
        Used for testing and diagnostics: list the constructor line numbers used to resolve this
         encoding
 
         <p>
         This includes braces to describe the tree structure
        @see ConstructState#dumpConstructorTree()
        @return the constructor tree
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def equivalentConstructState(self, state: ghidra.app.plugin.processors.sleigh.ConstructState) -> bool: ...

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

    @staticmethod
    def fromString(__a0: unicode, __a1: unicode, __a2: List[object]) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns: ...

    def getClass(self) -> java.lang.Class: ...

    def getContext(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock:
        """
        Get the context block
        @return the context block
        """
        ...

    def getDefinedInstructionLength(self) -> int:
        """
        Get the length of the instruction encoding, excluding trailing undefined bytes
 
         <p>
         <b>NOTE:</b> this DOES include the offset<br>
         <b>NOTE:</b> this DOES NOT include pending backfills
        @return the length of the defined bytes in the instruction block
        """
        ...

    def getInstruction(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock:
        """
        Get the instruction block
        @return the instruction block
        """
        ...

    def getInstructionLength(self) -> int:
        """
        Get the length of the instruction encoding
 
         <p>
         This is used to ensure each operand is encoded at the correct offset
 
         <p>
         <b>NOTE:</b> this DOES include the offset<br>
         <b>NOTE:</b> this DOES include pending backfills
        @return the length of the instruction block
        """
        ...

    def getSpecificity(self) -> int:
        """
        Count the number of bits specified in the resolution patterns
 
         <p>
         Totals the specificity of the instruction and context pattern blocks.
        @return the number of bits in the resulting patterns
        @see AssemblyPatternBlock#getSpecificity()
        """
        ...

    def hasBackfills(self) -> bool:
        """
        Check if this resolution has pending backfills to apply
        @return true if there are backfills
        """
        ...

    def hasChildren(self) -> bool: ...

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

    def lineToString(self) -> unicode: ...

    def maskOut(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Set all bits read by a given context operation to unknown
        @param cop the context operation
        @return the result
        @see AssemblyPatternBlock#maskOut(ContextOp)
        """
        ...

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

    def nopLeftSibling(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parent(self, description: unicode, opCount: int) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns: ...

    def possibleInsVals(self, forCtx: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock) -> List[java.lang.Iterable]:
        """
        Get an iterable over all the possible fillings of the instruction pattern given a context
 
         <p>
         This is meant to be used idiomatically, as in an enhanced for loop:
 
         <pre>
         for (byte[] ins : rcon.possibleInsVals(ctx)) {
         	System.out.println(format(ins));
         }
         </pre>
 
         <p>
         This is similar to calling
         {@link #getInstruction()}.{@link AssemblyPatternBlock#possibleVals()}, <em>but</em> with
         forbidden patterns removed. A context is required so that only those forbidden patterns
         matching the given context are actually removed. This method should always be preferred to
         the sequence mentioned above, since {@link AssemblyPatternBlock#possibleVals()} on its own
         may yield bytes that do not produce the desired instruction.
 
         <p>
         <b>NOTE:</b> The implementation is based on {@link AssemblyPatternBlock#possibleVals()}, so
         be aware that a single array is reused for each iterate. You should not retain a pointer to
         the array, but rather make a copy.
        @param forCtx the context at the assembly address
        @return the iterable
        """
        ...

    def readContext(self, start: int, len: int) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Decode a portion of the context block
        @param start the first byte to decode
        @param len the number of bytes to decode
        @return the read masked value
        @see AssemblyPatternBlock#readBytes(int, int)
        """
        ...

    def readContextOp(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Decode the value from the context located where the given context operation would write
 
         <p>
         This is used to read the value from the left-hand-side "variable" of a context operation. It
         seems backward, because it is. When assembling, the right-hand-side expression of a context
         operation must be solved. This means the "variable" is known from the context(s) of the
         resolved children constructors. The value read is then used as the goal in solving the
         expression.
        @param cop the context operation whose "variable" to read.
        @return the masked result.
        """
        ...

    def readInstruction(self, start: int, len: int) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Decode a portion of the instruction block
        @param start the first byte to decode
        @param len the number of bytes to decode
        @return the read masked value
        @see AssemblyPatternBlock#readBytes(int, int)
        """
        ...

    @staticmethod
    def resolved(__a0: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock, __a1: ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock, __a2: unicode, __a3: ghidra.app.plugin.processors.sleigh.Constructor, __a4: List[object], __a5: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns: ...

    def shift(self, amt: int) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns: ...

    def solveContextChangesForForbids(self, sem: ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic, vals: java.util.Map) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Solve and apply context changes in reverse to forbidden patterns
 
         <p>
         To avoid circumstances where a context change during disassembly would invoke a more specific
         sub-constructor than was used to assembly the instruction, we must solve the forbidden
         patterns in tandem with the overall resolution. If the context of any forbidden pattern
         cannot be solved, we simply drop the forbidden pattern -- the lack of a solution implies
         there is no way the context change could produce the forbidden pattern.
        @param sem the constructor whose context changes to solve
        @param vals any defined symbols
        @return the result
        @see AssemblyConstructorSemantic#solveContextChanges(AssemblyResolvedPatterns, Map)
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

    def truncate(self, amt: int) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Truncate (unshift) the resolved instruction pattern from the left
 
         <b>NOTE:</b> This drops all backfill and forbidden pattern records, since this method is
         typically used to read token fields rather than passed around for resolution.
        @param amt the number of bytes to remove from the left
        @return the result
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def withConstructor(self, cons: ghidra.app.plugin.processors.sleigh.Constructor) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Create a copy of this resolution with a replaced constructor
        @param cons the new constructor
        @return the copy
        """
        ...

    def withDescription(self, desc: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Create a copy of this resolution with a new description
        @param desc the new description
        @return the copy
        """
        ...

    def withForbids(self, more: java.util.Set) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Create a new resolution from this one with the given forbidden patterns recorded
        @param more the additional forbidden patterns to record
        @return the new resolution
        """
        ...

    def withRight(self, right: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns: ...

    def withoutRight(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Get this same resolution, but without any right siblings
        @return the resolution
        """
        ...

    def writeContextOp(self, cop: ghidra.app.plugin.processors.sleigh.ContextOp, val: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns:
        """
        Encode the given value into the context block as specified by an operation
        @param cop the context operation specifying the location of the value to encode
        @param val the masked value to encode
        @return the result
 
                 This is the forward (as in disassembly) direction of applying context operations. The
                 pattern expression is evaluated, and the result is written as specified.
        """
        ...

    @property
    def context(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock: ...

    @property
    def definedInstructionLength(self) -> int: ...

    @property
    def instruction(self) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock: ...

    @property
    def instructionLength(self) -> int: ...

    @property
    def specificity(self) -> int: ...