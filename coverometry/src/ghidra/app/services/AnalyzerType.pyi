from typing import List
import ghidra.app.services
import java.lang
import java.util


class AnalyzerType(java.lang.Enum):
    BYTE_ANALYZER: ghidra.app.services.AnalyzerType = Byte Analyzer
    DATA_ANALYZER: ghidra.app.services.AnalyzerType = Data Analyzer
    FUNCTION_ANALYZER: ghidra.app.services.AnalyzerType = Function Analyzer
    FUNCTION_MODIFIERS_ANALYZER: ghidra.app.services.AnalyzerType = Function-modifiers Analyzer
    FUNCTION_SIGNATURES_ANALYZER: ghidra.app.services.AnalyzerType = Function-Signatures Analyzer
    INSTRUCTION_ANALYZER: ghidra.app.services.AnalyzerType = Instructions Analyzer







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.services.AnalyzerType: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.services.AnalyzerType]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def description(self) -> unicode: ...