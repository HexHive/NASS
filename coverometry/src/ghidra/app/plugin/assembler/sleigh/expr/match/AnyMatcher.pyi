import ghidra.app.plugin.assembler.sleigh.expr.match
import ghidra.app.plugin.processors.sleigh.expression
import java.lang
import java.util


class AnyMatcher(ghidra.app.plugin.assembler.sleigh.expr.match.AbstractExpressionMatcher):
    """
    A matcher which accept any expression of the required type

 
     This requires no further consideration of the expressions operands. If the type matches, the
     expression matches.
    """





    @overload
    def __init__(self, cls: java.lang.Class): ...

    @overload
    def __init__(self, ops: java.util.Set): ...



    @staticmethod
    def any() -> ghidra.app.plugin.assembler.sleigh.expr.match.AnyMatcher: ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, __a0: java.util.Map) -> ghidra.app.plugin.processors.sleigh.expression.PatternExpression: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @overload
    def match(self, __a0: ghidra.app.plugin.processors.sleigh.expression.PatternExpression) -> java.util.Map: ...

    @overload
    def match(self, expression: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, result: java.util.Map) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

