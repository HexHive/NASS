from typing import List
import ghidra.app.plugin.processors.sleigh
import ghidra.app.plugin.processors.sleigh.pattern
import ghidra.xml
import java.lang


class DisjointPattern(ghidra.app.plugin.processors.sleigh.pattern.Pattern):
    """
    A pattern with no ORs in it
    """





    def __init__(self): ...



    def alwaysFalse(self) -> bool: ...

    def alwaysInstructionTrue(self) -> bool: ...

    def alwaysTrue(self) -> bool: ...

    def doAnd(self, b: ghidra.app.plugin.processors.sleigh.pattern.Pattern, sa: int) -> ghidra.app.plugin.processors.sleigh.pattern.Pattern: ...

    def doOr(self, b: ghidra.app.plugin.processors.sleigh.pattern.Pattern, sa: int) -> ghidra.app.plugin.processors.sleigh.pattern.Pattern: ...

    def equals(self, __a0: object) -> bool: ...

    def getBlock(self, context: bool) -> ghidra.app.plugin.processors.sleigh.pattern.PatternBlock: ...

    def getClass(self) -> java.lang.Class: ...

    def getContextBlock(self) -> ghidra.app.plugin.processors.sleigh.pattern.PatternBlock: ...

    def getDisjoint(self, i: int) -> ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern: ...

    def getInstructionBlock(self) -> ghidra.app.plugin.processors.sleigh.pattern.PatternBlock: ...

    def getLength(self, context: bool) -> int: ...

    def getMask(self, startbit: int, size: int, context: bool) -> int: ...

    def getValue(self, startbit: int, size: int, context: bool) -> int: ...

    def getWholeInstructionBytes(self) -> List[int]: ...

    def hashCode(self) -> int: ...

    def identical(self, op2: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern) -> bool: ...

    def isMatch(self, walker: ghidra.app.plugin.processors.sleigh.ParserWalker, debug: ghidra.app.plugin.processors.sleigh.SleighDebugLogger) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def numDisjoint(self) -> int: ...

    @staticmethod
    def restoreDisjoint(parser: ghidra.xml.XmlPullParser) -> ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern: ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser) -> None: ...

    def shiftInstruction(self, sa: int) -> None: ...

    def simplifyClone(self) -> ghidra.app.plugin.processors.sleigh.pattern.Pattern: ...

    def specializes(self, op2: ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def contextBlock(self) -> ghidra.app.plugin.processors.sleigh.pattern.PatternBlock: ...

    @property
    def instructionBlock(self) -> ghidra.app.plugin.processors.sleigh.pattern.PatternBlock: ...

    @property
    def wholeInstructionBytes(self) -> List[int]: ...