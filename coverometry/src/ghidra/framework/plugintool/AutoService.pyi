import ghidra.framework.plugintool
import java.lang


class AutoService(object):





    class Wiring(object):








        def dispose(self) -> None: ...

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






    class WiringImpl(object, ghidra.framework.plugintool.AutoService.Wiring):




        def __init__(self, __a0: ghidra.framework.plugintool.util.AutoServiceListener): ...



        def dispose(self) -> None: ...

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







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def registerServicesProvided(__a0: ghidra.framework.plugintool.Plugin, __a1: java.lang.Class, __a2: object) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @overload
    @staticmethod
    def wireServicesConsumed(__a0: ghidra.framework.plugintool.Plugin, __a1: object) -> ghidra.framework.plugintool.AutoService.Wiring: ...

    @overload
    @staticmethod
    def wireServicesConsumed(__a0: ghidra.framework.plugintool.PluginTool, __a1: object) -> ghidra.framework.plugintool.AutoService.Wiring: ...

    @staticmethod
    def wireServicesProvidedAndConsumed(__a0: ghidra.framework.plugintool.Plugin) -> ghidra.framework.plugintool.AutoService.Wiring: ...

