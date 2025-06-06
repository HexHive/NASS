import ghidra.program.model.listing
import java.lang


class RenameTask(object):




    def __init__(self, __a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.program.model.listing.Program, __a2: ghidra.app.plugin.core.decompile.DecompilerProvider, __a3: ghidra.app.decompiler.ClangToken, __a4: unicode): ...



    def commit(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getNewName(self) -> unicode: ...

    def getTransactionName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isSymbolInFunction(__a0: ghidra.program.model.listing.Function, __a1: unicode) -> bool: ...

    def isValid(self, __a0: unicode) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def runTask(self, __a0: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def newName(self) -> unicode: ...

    @property
    def transactionName(self) -> unicode: ...