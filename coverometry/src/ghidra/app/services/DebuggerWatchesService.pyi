import ghidra.app.plugin.core.debug.gui.watch
import java.lang
import java.util


class DebuggerWatchesService(object):








    def addWatch(self, __a0: unicode) -> ghidra.app.plugin.core.debug.gui.watch.WatchRow: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getWatches(self) -> java.util.Collection: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeWatch(self, __a0: ghidra.app.plugin.core.debug.gui.watch.WatchRow) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def watches(self) -> java.util.Collection: ...