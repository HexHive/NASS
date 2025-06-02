import ghidra.framework.options
import ghidra.framework.options.annotation
import ghidra.framework.plugintool
import ghidra.util
import java.lang
import java.lang.annotation


class AutoOptions(object):





    class OldValue(java.lang.annotation.Annotation, object):








        def annotationType(self) -> java.lang.Class: ...

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






    class WiringImpl(object, ghidra.framework.options.AutoOptions.Wiring):




        def __init__(self, __a0: ghidra.framework.options.AutoOptionsListener): ...



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






    class NewValue(java.lang.annotation.Annotation, object):








        def annotationType(self) -> java.lang.Class: ...

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






    class CategoryAndName(java.lang.Record, java.lang.Comparable):




        @overload
        def __init__(self, __a0: unicode, __a1: unicode): ...

        @overload
        def __init__(self, __a0: ghidra.framework.options.annotation.AutoOptionConsumed, __a1: ghidra.framework.plugintool.Plugin): ...

        @overload
        def __init__(self, __a0: ghidra.framework.options.annotation.AutoOptionDefined, __a1: ghidra.framework.plugintool.Plugin): ...



        def category(self) -> unicode: ...

        @overload
        def compareTo(self, __a0: ghidra.framework.options.AutoOptions.CategoryAndName) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

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

    @staticmethod
    def getHelpLocation(__a0: unicode, __a1: ghidra.framework.options.annotation.HelpInfo) -> ghidra.util.HelpLocation: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def registerOptionsDefined(__a0: ghidra.framework.plugintool.Plugin, __a1: java.lang.Class, __a2: object) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @overload
    @staticmethod
    def wireOptions(__a0: ghidra.framework.plugintool.Plugin) -> ghidra.framework.options.AutoOptions.Wiring: ...

    @overload
    @staticmethod
    def wireOptions(__a0: ghidra.framework.plugintool.Plugin, __a1: object) -> ghidra.framework.options.AutoOptions.Wiring: ...

    @staticmethod
    def wireOptionsConsumed(__a0: ghidra.framework.plugintool.Plugin, __a1: object) -> ghidra.framework.options.AutoOptions.Wiring: ...

