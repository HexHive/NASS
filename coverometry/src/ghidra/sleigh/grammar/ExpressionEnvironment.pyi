import java.lang


class ExpressionEnvironment(object):








    def equals(self, lhs: unicode, rhs: unicode) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def lookup(self, variable: unicode) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def reportError(self, msg: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

