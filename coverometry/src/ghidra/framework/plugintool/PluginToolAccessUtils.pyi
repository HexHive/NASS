import ghidra.framework.plugintool
import java.lang


class PluginToolAccessUtils(object):
    """
    Utility class to provide access to non-public methods on PluginTool. There are a number of
     methods that internal classes need access to but we don't want on the public interface of
     PluginTool.This is a stopgap approach until we clean up the package structure for tool related
     classes and interfaces. This class should only be used by internal tool manager classes.
    """









    @staticmethod
    def canClose(tool: ghidra.framework.plugintool.PluginTool) -> bool:
        """
        Returns true if the tool can be closed. Note this does not handle any data saving. It only
         checks that there are no tasks running and the plugins can be closed.
        @param tool the tool to close
        @return true if the tool can be closed
        """
        ...

    @staticmethod
    def dispose(tool: ghidra.framework.plugintool.PluginTool) -> None:
        """
        Disposes the tool.
        @param tool the tool to dispose
        """
        ...

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

