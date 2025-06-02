from typing import List
import ghidra.app.plugin.core.debug.mapping
import ghidra.dbg.target
import ghidra.program.model.lang
import java.lang
import java.util


class DbgengX64DebuggerMappingOpinion(object, ghidra.app.plugin.core.debug.mapping.DebuggerMappingOpinion):
    HIGHEST_CONFIDENCE_FIRST: java.util.Comparator = java.util.Comparator$$Lambda$156/0x00000001003c2338@52279fe



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getEndian(__a0: ghidra.dbg.target.TargetEnvironment) -> ghidra.program.model.lang.Endian: ...

    def getOffers(self, __a0: ghidra.dbg.target.TargetObject, __a1: bool) -> java.util.Set: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def offersForEnv(self, __a0: ghidra.dbg.target.TargetEnvironment, __a1: ghidra.dbg.target.TargetObject, __a2: bool) -> java.util.Set: ...

    @staticmethod
    def queryOpinions(__a0: ghidra.dbg.target.TargetObject, __a1: bool) -> List[object]: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

