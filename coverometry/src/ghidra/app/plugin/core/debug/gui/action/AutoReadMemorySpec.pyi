import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui.action
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.util.classfinder
import java.lang
import java.util
import java.util.concurrent
import javax.swing


class AutoReadMemorySpec(ghidra.util.classfinder.ExtensionPoint, object):
    PRIVATE: ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec.Private = ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec$Private@40c1263a




    class AutoReadMemorySpecConfigFieldCodec(object, ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec):




        def __init__(self): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        @overload
        def read(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec) -> ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec: ...

        @overload
        def read(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: object) -> object: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @overload
        def write(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec) -> None: ...

        @overload
        def write(self, __a0: ghidra.framework.options.SaveState, __a1: unicode, __a2: object) -> None: ...






    class Private(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    @staticmethod
    def allSpecs() -> java.util.Map: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromConfigName(__a0: unicode) -> ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec: ...

    def getClass(self) -> java.lang.Class: ...

    def getConfigName(self) -> unicode: ...

    def getMenuIcon(self) -> javax.swing.Icon: ...

    def getMenuName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readMemory(self, __a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.app.plugin.core.debug.DebuggerCoordinates, __a2: ghidra.program.model.address.AddressSetView) -> java.util.concurrent.CompletableFuture: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def configName(self) -> unicode: ...

    @property
    def menuIcon(self) -> javax.swing.Icon: ...

    @property
    def menuName(self) -> unicode: ...