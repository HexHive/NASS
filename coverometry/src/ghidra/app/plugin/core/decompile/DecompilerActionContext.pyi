import docking
import ghidra.app.context
import ghidra.app.decompiler
import ghidra.app.decompiler.component
import ghidra.app.nav
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.util
import java.awt
import java.awt.event
import java.lang
import java.util.function
import utility.function


class DecompilerActionContext(ghidra.app.context.NavigatableActionContext, ghidra.app.context.RestrictedAddressSetContext):




    @overload
    def __init__(self, __a0: ghidra.app.plugin.core.decompile.DecompilerProvider, __a1: ghidra.program.model.address.Address, __a2: bool): ...

    @overload
    def __init__(self, __a0: ghidra.app.plugin.core.decompile.DecompilerProvider, __a1: ghidra.program.model.address.Address, __a2: bool, __a3: int): ...



    def checkActionEnablement(self, __a0: java.util.function.Supplier) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getCCodeModel(self) -> ghidra.app.decompiler.ClangTokenGroup: ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeUnit(self) -> ghidra.program.model.listing.CodeUnit: ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getContextObject(self) -> object: ...

    def getDecompilerPanel(self) -> ghidra.app.decompiler.component.DecompilerPanel: ...

    def getEventClickModifiers(self) -> int: ...

    def getFunction(self) -> ghidra.program.model.listing.Function: ...

    def getFunctionEntryPoint(self) -> ghidra.program.model.address.Address: ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction: ...

    def getHighlight(self) -> ghidra.program.util.ProgramSelection: ...

    def getLineNumber(self) -> int: ...

    def getLocation(self) -> ghidra.program.util.ProgramLocation: ...

    def getMouseEvent(self) -> java.awt.event.MouseEvent: ...

    def getNavigatable(self) -> ghidra.app.nav.Navigatable: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getSelection(self) -> ghidra.program.util.ProgramSelection: ...

    def getSourceComponent(self) -> java.awt.Component: ...

    def getSourceObject(self) -> object: ...

    def getTokenAtCursor(self) -> ghidra.app.decompiler.ClangToken: ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool: ...

    def hasAnyEventClickModifiers(self, __a0: int) -> bool: ...

    def hasHighlight(self) -> bool: ...

    def hasRealFunction(self) -> bool: ...

    def hasSelection(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isDecompiling(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def performAction(self, __a0: utility.function.Callback) -> None: ...

    def setContextObject(self, __a0: object) -> docking.ActionContext: ...

    def setEventClickModifiers(self, __a0: int) -> None: ...

    def setMouseEvent(self, __a0: java.awt.event.MouseEvent) -> docking.ActionContext: ...

    def setSourceObject(self, __a0: object) -> docking.ActionContext: ...

    def setStatusMessage(self, __a0: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def CCodeModel(self) -> ghidra.app.decompiler.ClangTokenGroup: ...

    @property
    def componentProvider(self) -> ghidra.app.plugin.core.decompile.DecompilerProvider: ...

    @property
    def decompilerPanel(self) -> ghidra.app.decompiler.component.DecompilerPanel: ...

    @property
    def decompiling(self) -> bool: ...

    @property
    def function(self) -> ghidra.program.model.listing.Function: ...

    @property
    def functionEntryPoint(self) -> ghidra.program.model.address.Address: ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction: ...

    @property
    def lineNumber(self) -> int: ...

    @property
    def statusMessage(self) -> None: ...  # No getter available.

    @statusMessage.setter
    def statusMessage(self, value: unicode) -> None: ...

    @property
    def tokenAtCursor(self) -> ghidra.app.decompiler.ClangToken: ...

    @property
    def tool(self) -> ghidra.framework.plugintool.PluginTool: ...