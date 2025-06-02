import ghidra.app.plugin.assembler.sleigh.expr
import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.processors.sleigh.expression
import java.lang
import java.util


class RecursiveDescentSolver(object):
    """
    This singleton class seeks solutions to PatternExpressions
 
 
     It is rather naive. It does not perform algebraic transformations. Instead, it attempts to fold
     constants, assuming there is a single variable in the expression, modifying the goal as it
     descends toward that variable. If it finds a variable, i.e., token or context field, it encodes
     the solution, positioned in the field. If the expression is constant, it checks that the goal
     agrees. If not, an error is returned. There are some common cases where it is forced to solve
     expressions involving multiple variables. Those cases are addressed in the derivatives of
     AbstractBinaryExpressionSolver where the situation can be detected. One common example is
     field concatenation using the  pattern.
 
 
     TODO: Perhaps this whole mechanism ought to just be factored directly into
     PatternExpression.
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getInstructionLength(self, exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression) -> int:
        """
        Determine the length of the instruction part of the encoded solution to the given expression
 
         <p>
         This is used to keep operands in their appropriate position when backfilling becomes
         applicable. Normally, the instruction length is taken from the encoding of a solution, but if
         the solution cannot be determined yet, the instruction length must still be obtained.
 
         <p>
         The length can be determined by finding token fields in the expression.
        @param exp the expression, presumably containing a token field
        @return the anticipated length, in bytes, of the instruction encoding
        """
        ...

    @staticmethod
    def getSolver() -> ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver:
        """
        Obtain an instance of the naive solver
        @return the singleton instance
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def solve(self, exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, goal: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong, vals: java.util.Map, cur: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, description: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution:
        """
        Solve a given expression, given a masked-value goal
 
         <p>
         From a simplified perspective, we need only the expression and the desired value to solve it.
         Generally speaking, the expression may only contain a single field, and the encoded result
         specifies the bits of the solved field. It must be absorbed into the overall assembly
         pattern.
 
         <p>
         More realistically, these expressions may depend on quite a bit of extra information. For
         example, PC-relative encodings (i.e., those involving {@code inst_start} or
         {@code inst_next}, need to know the starting address of the resulting instruction. {@code
         inst_start} must be provided to the solver by the assembler. {@code inst_next} cannot be
         known until the instruction length is known. Thus, expressions using it always result in a
         {@link NeedsBackfillException}. The symbols, when known, are provided to the solver via the
         {@code vals} parameter.
        @param exp the expression to solve
        @param goal the desired output (modulo a mask) of the expression
        @param vals any defined symbols (usually {@code inst_start}, and {@code inst_next})
        @param description a description to attached to the encoded solution
        @return the encoded solution
        @throws NeedsBackfillException a solution may exist, but a required symbol is missing
        """
        ...

    def toString(self) -> unicode: ...

    def valueForResolution(self, exp: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, vals: java.util.Map, rc: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong:
        """
        Compute the value of an expression given a (possibly-intermediate) resolution
        @param exp the expression to evaluate
        @param vals values of defined symbols
        @param rc the resolution on which to evaluate it
        @return the result
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

