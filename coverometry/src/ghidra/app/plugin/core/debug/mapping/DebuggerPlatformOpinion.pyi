from typing import List
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.target
import ghidra.util.classfinder
import java.lang
import java.util


class DebuggerPlatformOpinion(ghidra.util.classfinder.ExtensionPoint, object):
    HIGHEST_CONFIDENCE_FIRST: java.util.Comparator = java.util.Comparator$$Lambda$156/0x00000001003c2338@4649eb9d







    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getArchitectureFromEnv(__a0: ghidra.trace.model.target.TraceObject, __a1: long) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getDebugggerFromEnv(__a0: ghidra.trace.model.target.TraceObject, __a1: long) -> unicode: ...

    @staticmethod
    def getEndianFromEnv(__a0: ghidra.trace.model.target.TraceObject, __a1: long) -> ghidra.program.model.lang.Endian: ...

    @staticmethod
    def getEnvironment(__a0: ghidra.trace.model.target.TraceObject, __a1: long) -> ghidra.trace.model.target.TraceObject: ...

    def getOffers(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.trace.model.target.TraceObject, __a2: long, __a3: bool) -> java.util.Set: ...

    @staticmethod
    def getOperatingSystemFromEnv(__a0: ghidra.trace.model.target.TraceObject, __a1: long) -> unicode: ...

    @staticmethod
    def getStringAttribute(__a0: ghidra.trace.model.target.TraceObject, __a1: long, __a2: unicode) -> unicode: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def queryOpinions(__a0: ghidra.trace.model.Trace, __a1: ghidra.trace.model.target.TraceObject, __a2: long, __a3: bool) -> List[object]: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

