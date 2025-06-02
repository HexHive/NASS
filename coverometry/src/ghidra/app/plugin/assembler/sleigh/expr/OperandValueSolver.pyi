import ghidra.app.plugin.assembler.sleigh.expr
import ghidra.app.plugin.assembler.sleigh.sem
import ghidra.app.plugin.processors.sleigh.expression
import ghidra.app.plugin.processors.sleigh.symbol
import java.lang
import java.util


class OperandValueSolver(ghidra.app.plugin.assembler.sleigh.expr.AbstractExpressionSolver):
    """
    Solves expressions of an operand value
 
 
     These are a sort of named sub-expression, but they may also specify a shift in encoding.
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getDefiningExpression(sym: ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression:
        """
        Obtains the "defining expression"
 
         <p>
         This is either the symbols assigned defining expression, or the expression associated with
         its defining symbol.
        @return the defining expression, or null if neither is available
        """
        ...

    @overload
    def getInstructionLength(self, ov: ghidra.app.plugin.processors.sleigh.expression.OperandValue) -> int: ...

    @overload
    def getInstructionLength(self, __a0: ghidra.app.plugin.processors.sleigh.expression.PatternExpression) -> int: ...

    @overload
    def getValue(self, ov: ghidra.app.plugin.processors.sleigh.expression.OperandValue, vals: java.util.Map, cur: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong: ...

    @overload
    def getValue(self, __a0: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, __a1: java.util.Map, __a2: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def solve(self, ov: ghidra.app.plugin.processors.sleigh.expression.OperandValue, goal: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong, vals: java.util.Map, cur: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, hints: java.util.Set, description: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution: ...

    @overload
    def solve(self, __a0: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, __a1: ghidra.app.plugin.assembler.sleigh.expr.MaskedLong, __a2: java.util.Map, __a3: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns, __a4: java.util.Set, __a5: unicode) -> ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution: ...

    def toString(self) -> unicode: ...

    @overload
    def valueForResolution(self, ov: ghidra.app.plugin.processors.sleigh.expression.OperandValue, vals: java.util.Map, rc: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong: ...

    @overload
    def valueForResolution(self, __a0: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, __a1: java.util.Map, __a2: ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns) -> ghidra.app.plugin.assembler.sleigh.expr.MaskedLong: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

