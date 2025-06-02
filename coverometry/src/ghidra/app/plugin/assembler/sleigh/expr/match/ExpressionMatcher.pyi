import ghidra.app.plugin.assembler.sleigh.expr.match
import ghidra.app.plugin.processors.sleigh.expression
import java.lang
import java.util


class ExpressionMatcher(object):
    """
    A matcher for a form of patten expression

 
     Some solvers may need to apply sophisticated heuristics to recognize certain forms that commonly
     occur in pattern expressions. These can certainly be programmed manually, but for many cases, the
     form recognition can be accomplished by describing the form as an expression matcher. For a
     shorter syntax to construct such matchers. See Context.
    """






    class Context(object):








        def and(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def cv(self, __a0: long) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def div(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def equals(self, __a0: object) -> bool: ...

        def fldSz(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def mul(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def neg(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def not(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def opnd(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def or(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def plus(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def shl(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def shr(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def sub(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        def toString(self) -> unicode: ...

        @overload
        def var(self) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        @overload
        def var(self, __a0: java.lang.Class) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        def xor(self, __a0: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher, __a1: ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher) -> ghidra.app.plugin.assembler.sleigh.expr.match.ExpressionMatcher: ...







    def equals(self, __a0: object) -> bool: ...

    def get(self, results: java.util.Map) -> object:
        """
        Retrieve the expression substituted for this matcher from a previous successful match
 
         <p>
         Calling this on the root matcher is relatively useless, as it would simply return the
         expression passed to {@link #match(PatternExpression)}. Instead, sub-matchers should be saved
         in a variable, allowing their values to be retrieved. See {@link Context}, for an example.
        @param results the previous match results
        @return the substituted expression
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @overload
    def match(self, expression: ghidra.app.plugin.processors.sleigh.expression.PatternExpression) -> java.util.Map:
        """
        Attempt to match the given expression, recording the substitutions if successful
        @param expression the expression to match
        @return a map of matchers to substituted expressions
        """
        ...

    @overload
    def match(self, expression: ghidra.app.plugin.processors.sleigh.expression.PatternExpression, result: java.util.Map) -> bool:
        """
        Attempt to match the given expression, recording substitutions in the given map
 
         <p>
         Even if the match was unsuccessful, the result map may contain attempted substitutions. Thus,
         the map should be discarded if unsuccessful.
        @param expression the expression to match
        @param result a map to store matchers to substituted expressions
        @return true if successful, false if not
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

