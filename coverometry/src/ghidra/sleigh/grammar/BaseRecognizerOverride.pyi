from typing import List
import ghidra.sleigh.grammar
import java.lang
import org.antlr.runtime


class BaseRecognizerOverride(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getErrorMessage(self, e: org.antlr.runtime.RecognitionException, tokenNames: List[unicode], writer: ghidra.sleigh.grammar.LineArrayListWriter) -> unicode: ...

    def getTokenErrorDisplay(self, t: org.antlr.runtime.Token) -> unicode: ...

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

