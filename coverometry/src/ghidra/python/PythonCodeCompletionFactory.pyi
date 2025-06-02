from typing import List
import ghidra.app.plugin.core.console
import ghidra.framework.options
import ghidra.python
import java.lang


class PythonCodeCompletionFactory(object):
    """
    Generates CodeCompletions from Python objects.
    """

    CLASS_COLOR: java.awt.Color = #00ffff
    CODE_COLOR: java.awt.Color = #00ffff
    COMPLETION_LABEL: unicode = u'Code Completion Colors'
    FUNCTION_COLOR: java.awt.Color = #00ffff
    INSTANCE_COLOR: java.awt.Color = #00ffff
    MAP_COLOR: java.awt.Color = #00ffff
    METHOD_COLOR: java.awt.Color = #00ffff
    NULL_COLOR: java.awt.Color = #00ffff
    NUMBER_COLOR: java.awt.Color = #00ffff
    PACKAGE_COLOR: java.awt.Color = #00ffff
    SEQUENCE_COLOR: java.awt.Color = #00ffff
    SPECIAL_COLOR: java.awt.Color = #00ffff



    def __init__(self): ...



    @staticmethod
    def changeOptions(options: ghidra.framework.options.Options, name: unicode, oldValue: object, newValue: object) -> None:
        """
        Handle an Option change.
 
         This is named slightly differently because it is a static method, not
         an instance method.
 
         By the time we get here, we assume that the Option changed is indeed
         ours.
        @param options the Options handle
        @param name name of the Option changed
        @param oldValue the old value
        @param newValue the new value
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getCallMethods(__a0: object) -> List[object]: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @overload
    @staticmethod
    def newCodeCompletion(__a0: unicode, __a1: unicode, __a2: object) -> ghidra.app.plugin.core.console.CodeCompletion: ...

    @overload
    @staticmethod
    def newCodeCompletion(__a0: unicode, __a1: unicode, __a2: object, __a3: unicode) -> ghidra.app.plugin.core.console.CodeCompletion: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def setupOptions(plugin: ghidra.python.PythonPlugin, options: ghidra.framework.options.Options) -> None:
        """
        Sets up Python code completion Options.
        @param plugin python plugin as options owner
        @param options an Options handle
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

