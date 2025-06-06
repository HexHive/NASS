import ghidra.dbg
import ghidra.framework.plugintool
import java.lang


class ModelActivatedPluginEvent(ghidra.framework.plugintool.PluginEvent):




    def __init__(self, __a0: unicode, __a1: ghidra.dbg.DebuggerObjectModel): ...



    def equals(self, __a0: object) -> bool: ...

    def getActiveModel(self) -> ghidra.dbg.DebuggerObjectModel: ...

    def getClass(self) -> java.lang.Class: ...

    def getEventName(self) -> unicode: ...

    def getSourceName(self) -> unicode: ...

    def getToolEventName(self) -> unicode: ...

    def getTriggerEvent(self) -> ghidra.framework.plugintool.PluginEvent: ...

    def hashCode(self) -> int: ...

    def isToolEvent(self) -> bool: ...

    @staticmethod
    def lookupToolEventName(__a0: java.lang.Class) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setSourceName(self, __a0: unicode) -> None: ...

    def setTriggerEvent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def activeModel(self) -> ghidra.dbg.DebuggerObjectModel: ...