from typing import List
import ghidra.pcode.exec
import ghidra.pcode.exec.trace
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.thread
import java.lang
import java.util
import org.apache.commons.lang3.tuple


class TraceSleighUtils(java.lang.Enum):








    @overload
    @staticmethod
    def buildByteExecutor(__a0: ghidra.trace.model.Trace, __a1: long, __a2: ghidra.trace.model.thread.TraceThread, __a3: int) -> ghidra.pcode.exec.PcodeExecutor: ...

    @overload
    @staticmethod
    def buildByteExecutor(__a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.trace.model.thread.TraceThread, __a3: int) -> ghidra.pcode.exec.PcodeExecutor: ...

    @overload
    @staticmethod
    def buildByteWithStateExecutor(__a0: ghidra.trace.model.Trace, __a1: long, __a2: ghidra.trace.model.thread.TraceThread, __a3: int) -> ghidra.pcode.exec.PcodeExecutor: ...

    @overload
    @staticmethod
    def buildByteWithStateExecutor(__a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.trace.model.thread.TraceThread, __a3: int) -> ghidra.pcode.exec.PcodeExecutor: ...

    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    @staticmethod
    def evaluate(__a0: unicode, __a1: ghidra.trace.model.Trace, __a2: long, __a3: ghidra.trace.model.thread.TraceThread, __a4: int) -> long: ...

    @overload
    @staticmethod
    def evaluate(__a0: ghidra.pcode.exec.PcodeExpression, __a1: ghidra.trace.model.Trace, __a2: long, __a3: ghidra.trace.model.thread.TraceThread, __a4: int) -> long: ...

    @overload
    @staticmethod
    def evaluateBytes(__a0: unicode, __a1: ghidra.trace.model.Trace, __a2: long, __a3: ghidra.trace.model.thread.TraceThread, __a4: int) -> List[int]: ...

    @overload
    @staticmethod
    def evaluateBytes(__a0: ghidra.pcode.exec.PcodeExpression, __a1: ghidra.trace.model.Trace, __a2: long, __a3: ghidra.trace.model.thread.TraceThread, __a4: int) -> List[int]: ...

    @overload
    @staticmethod
    def evaluateBytesWithState(__a0: unicode, __a1: ghidra.trace.model.Trace, __a2: long, __a3: ghidra.trace.model.thread.TraceThread, __a4: int) -> java.util.Map.Entry: ...

    @overload
    @staticmethod
    def evaluateBytesWithState(__a0: ghidra.pcode.exec.PcodeExpression, __a1: ghidra.trace.model.Trace, __a2: long, __a3: ghidra.trace.model.thread.TraceThread, __a4: int) -> org.apache.commons.lang3.tuple.Pair: ...

    @overload
    @staticmethod
    def evaluateWithState(__a0: unicode, __a1: ghidra.trace.model.Trace, __a2: long, __a3: ghidra.trace.model.thread.TraceThread, __a4: int) -> java.util.Map.Entry: ...

    @overload
    @staticmethod
    def evaluateWithState(__a0: ghidra.pcode.exec.PcodeExpression, __a1: ghidra.trace.model.Trace, __a2: long, __a3: ghidra.trace.model.thread.TraceThread, __a4: int) -> org.apache.commons.lang3.tuple.Pair: ...

    @staticmethod
    def generateExpressionForRange(__a0: ghidra.program.model.lang.Language, __a1: ghidra.program.model.address.AddressRange) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.pcode.exec.trace.TraceSleighUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.pcode.exec.trace.TraceSleighUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

