from typing import List
import ghidra.app.plugin.core.debug.mapping
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.target
import java.lang
import java.util


class DbgengDebuggerPlatformOpinion(ghidra.app.plugin.core.debug.mapping.AbstractDebuggerPlatformOpinion):




    def __init__(self): ...



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

