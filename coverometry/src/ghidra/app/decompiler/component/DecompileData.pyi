import docking.widgets.fieldpanel.support
import ghidra.app.decompiler
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.util
import java.io
import java.lang


class DecompileData(object):




    def __init__(self, program: ghidra.program.model.listing.Program, function: ghidra.program.model.listing.Function, location: ghidra.program.util.ProgramLocation, decompileResults: ghidra.app.decompiler.DecompileResults, errorMessage: unicode, debugFile: java.io.File, viewerPosition: docking.widgets.fieldpanel.support.ViewerPosition): ...



    def contains(self, programLocation: ghidra.program.util.ProgramLocation) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getCCodeMarkup(self) -> ghidra.app.decompiler.ClangTokenGroup: ...

    def getClass(self) -> java.lang.Class: ...

    def getDebugFile(self) -> java.io.File: ...

    def getDecompileResults(self) -> ghidra.app.decompiler.DecompileResults: ...

    def getErrorMessage(self) -> unicode: ...

    def getFunction(self) -> ghidra.program.model.listing.Function: ...

    def getFunctionSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    def getHighFunction(self) -> ghidra.program.model.pcode.HighFunction: ...

    def getLocation(self) -> ghidra.program.util.ProgramLocation: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getViewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition: ...

    def hasDecompileResults(self) -> bool: ...

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

    @property
    def CCodeMarkup(self) -> ghidra.app.decompiler.ClangTokenGroup: ...

    @property
    def debugFile(self) -> java.io.File: ...

    @property
    def decompileResults(self) -> ghidra.app.decompiler.DecompileResults: ...

    @property
    def errorMessage(self) -> unicode: ...

    @property
    def function(self) -> ghidra.program.model.listing.Function: ...

    @property
    def functionSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def highFunction(self) -> ghidra.program.model.pcode.HighFunction: ...

    @property
    def location(self) -> ghidra.program.util.ProgramLocation: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def viewerPosition(self) -> docking.widgets.fieldpanel.support.ViewerPosition: ...