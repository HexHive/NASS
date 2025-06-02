from typing import List
import ghidra.app.util.pcode
import ghidra.program.model.address
import ghidra.program.model.lang
import java.awt
import java.lang


class AttributedStringPcodeFormatter(ghidra.app.util.pcode.AbstractPcodeFormatter):




    def __init__(self):
        """
        Constructor
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    @overload
    def formatOps(self, __a0: ghidra.program.model.lang.Language, __a1: List[object]) -> object: ...

    @overload
    def formatOps(self, __a0: ghidra.program.model.lang.Language, __a1: ghidra.program.model.address.AddressFactory, __a2: List[object]) -> object: ...

    def formatTemplates(self, __a0: ghidra.program.model.lang.Language, __a1: List[object]) -> object: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getPcodeOpTemplates(__a0: ghidra.program.model.address.AddressFactory, __a1: List[object]) -> List[object]: ...

    def hashCode(self) -> int: ...

    def isFormatRaw(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setFontMetrics(self, metrics: java.awt.FontMetrics) -> None:
        """
        Set font metrics for AttributedString objects
        @param metrics the font metrics
        """
        ...

    def setOptions(self, maxDisplayLines: int, displayRawPcode: bool) -> None:
        """
        Set general formatting options
        @param maxDisplayLines the maximum number of lines to display
        @param displayRawPcode show raw pcode
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def fontMetrics(self) -> None: ...  # No getter available.

    @fontMetrics.setter
    def fontMetrics(self, value: java.awt.FontMetrics) -> None: ...

    @property
    def formatRaw(self) -> bool: ...