from typing import List
import ghidra.app.plugin.core.debug
import ghidra.app.services
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.trace.model
import ghidra.trace.model.program
import java.lang
import java.util.concurrent


class DebuggerControlService(object):





    class ControlModeChangeListener(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def modeChanged(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.app.services.ControlMode) -> None: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class StateEditor(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getCoordinates(self) -> ghidra.app.plugin.core.debug.DebuggerCoordinates: ...

        def getService(self) -> ghidra.app.services.DebuggerControlService: ...

        def hashCode(self) -> int: ...

        def isRegisterEditable(self, __a0: ghidra.program.model.lang.Register) -> bool: ...

        def isVariableEditable(self, __a0: ghidra.program.model.address.Address, __a1: int) -> bool: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def setRegister(self, __a0: ghidra.program.model.lang.RegisterValue) -> java.util.concurrent.CompletableFuture: ...

        def setVariable(self, __a0: ghidra.program.model.address.Address, __a1: List[int]) -> java.util.concurrent.CompletableFuture: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def coordinates(self) -> ghidra.app.plugin.core.debug.DebuggerCoordinates: ...

        @property
        def register(self) -> None: ...  # No getter available.

        @register.setter
        def register(self, value: ghidra.program.model.lang.RegisterValue) -> None: ...

        @property
        def service(self) -> ghidra.app.services.DebuggerControlService: ...




    class StateEditingMemoryHandler(ghidra.app.services.DebuggerControlService.StateEditor, ghidra.program.model.mem.LiveMemoryHandler, object):








        def addLiveMemoryListener(self, __a0: ghidra.program.model.mem.LiveMemoryListener) -> None: ...

        def clearCache(self) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        def getByte(self, __a0: ghidra.program.model.address.Address) -> int: ...

        def getBytes(self, __a0: ghidra.program.model.address.Address, __a1: List[int], __a2: int, __a3: int) -> int: ...

        def getClass(self) -> java.lang.Class: ...

        def getCoordinates(self) -> ghidra.app.plugin.core.debug.DebuggerCoordinates: ...

        def getService(self) -> ghidra.app.services.DebuggerControlService: ...

        def hashCode(self) -> int: ...

        def isRegisterEditable(self, __a0: ghidra.program.model.lang.Register) -> bool: ...

        def isVariableEditable(self, __a0: ghidra.program.model.address.Address, __a1: int) -> bool: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def putByte(self, __a0: ghidra.program.model.address.Address, __a1: int) -> None: ...

        def putBytes(self, __a0: ghidra.program.model.address.Address, __a1: List[int], __a2: int, __a3: int) -> int: ...

        def removeLiveMemoryListener(self, __a0: ghidra.program.model.mem.LiveMemoryListener) -> None: ...

        def setRegister(self, __a0: ghidra.program.model.lang.RegisterValue) -> java.util.concurrent.CompletableFuture: ...

        def setVariable(self, __a0: ghidra.program.model.address.Address, __a1: List[int]) -> java.util.concurrent.CompletableFuture: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def coordinates(self) -> ghidra.app.plugin.core.debug.DebuggerCoordinates: ...

        @property
        def register(self) -> None: ...  # No getter available.

        @register.setter
        def register(self, value: ghidra.program.model.lang.RegisterValue) -> None: ...

        @property
        def service(self) -> ghidra.app.services.DebuggerControlService: ...





    def addModeChangeListener(self, __a0: ghidra.app.services.DebuggerControlService.ControlModeChangeListener) -> None: ...

    @overload
    def createStateEditor(self, __a0: ghidra.app.plugin.core.debug.DebuggerCoordinates) -> ghidra.app.services.DebuggerControlService.StateEditor: ...

    @overload
    def createStateEditor(self, __a0: ghidra.trace.model.Trace) -> ghidra.app.services.DebuggerControlService.StateEditor: ...

    @overload
    def createStateEditor(self, __a0: ghidra.trace.model.program.TraceProgramView) -> ghidra.app.services.DebuggerControlService.StateEditingMemoryHandler: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCurrentMode(self, __a0: ghidra.trace.model.Trace) -> ghidra.app.services.ControlMode: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeModeChangeListener(self, __a0: ghidra.app.services.DebuggerControlService.ControlModeChangeListener) -> None: ...

    def setCurrentMode(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.app.services.ControlMode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

