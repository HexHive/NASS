import generic.stl
import ghidra.pcodeCPort.slghpatexpress
import ghidra.pcodeCPort.translate
import ghidra.pcodeCPort.utils
import java.io
import java.lang
import org.jdom


class RightShiftExpression(ghidra.pcodeCPort.slghpatexpress.BinaryExpression):
    location: ghidra.sleigh.grammar.Location



    @overload
    def __init__(self, __a0: ghidra.sleigh.grammar.Location): ...

    @overload
    def __init__(self, __a0: ghidra.sleigh.grammar.Location, __a1: ghidra.pcodeCPort.slghpatexpress.PatternExpression, __a2: ghidra.pcodeCPort.slghpatexpress.PatternExpression): ...



    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def genMinPattern(self, __a0: generic.stl.VectorSTL) -> ghidra.pcodeCPort.slghpatexpress.TokenPattern: ...

    def getClass(self) -> java.lang.Class: ...

    def getLeft(self) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression: ...

    def getMinMax(self, __a0: generic.stl.VectorSTL, __a1: generic.stl.VectorSTL) -> None: ...

    def getRight(self) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression: ...

    @overload
    def getSubValue(self, __a0: generic.stl.VectorSTL) -> long: ...

    @overload
    def getSubValue(self, __a0: generic.stl.VectorSTL, __a1: ghidra.pcodeCPort.utils.MutableInt) -> long: ...

    def hashCode(self) -> int: ...

    def layClaim(self) -> None: ...

    def listValues(self, __a0: generic.stl.VectorSTL) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def release(__a0: ghidra.pcodeCPort.slghpatexpress.PatternExpression) -> None: ...

    @staticmethod
    def restoreExpression(__a0: org.jdom.Element, __a1: ghidra.pcodeCPort.translate.Translate) -> ghidra.pcodeCPort.slghpatexpress.PatternExpression: ...

    def restoreXml(self, __a0: org.jdom.Element, __a1: ghidra.pcodeCPort.translate.Translate) -> None: ...

    def saveXml(self, __a0: java.io.PrintStream) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

