from typing import List
import docking
import ghidra.app.plugin.core.clipboard
import ghidra.app.util
import ghidra.app.util.viewer.listingpanel
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.task
import java.awt.datatransfer
import java.lang
import javax.swing.event


class FGClipboardProvider(ghidra.app.plugin.core.clipboard.CodeBrowserClipboardProvider):








    def addChangeListener(self, __a0: javax.swing.event.ChangeListener) -> None: ...

    def canCopy(self) -> bool: ...

    def canCopySpecial(self) -> bool: ...

    def canPaste(self, __a0: List[java.awt.datatransfer.DataFlavor]) -> bool: ...

    def copy(self, __a0: ghidra.util.task.TaskMonitor) -> java.awt.datatransfer.Transferable: ...

    def copySpecial(self, __a0: ghidra.app.util.ClipboardType, __a1: ghidra.util.task.TaskMonitor) -> java.awt.datatransfer.Transferable: ...

    @staticmethod
    def createStringTransferable(__a0: unicode) -> java.awt.datatransfer.Transferable: ...

    def enableCopy(self) -> bool: ...

    def enableCopySpecial(self) -> bool: ...

    def enablePaste(self) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getCurrentCopyTypes(self) -> List[object]: ...

    def getStringContent(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isValidContext(self, __a0: docking.ActionContext) -> bool: ...

    def lostOwnership(self, __a0: java.awt.datatransfer.Transferable) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def paste(self, __a0: java.awt.datatransfer.Transferable) -> bool: ...

    def removeChangeListener(self, __a0: javax.swing.event.ChangeListener) -> None: ...

    def setListingLayoutModel(self, __a0: ghidra.app.util.viewer.listingpanel.ListingModel) -> None: ...

    def setLocation(self, __a0: ghidra.program.util.ProgramLocation) -> None: ...

    def setProgram(self, __a0: ghidra.program.model.listing.Program) -> None: ...

    def setSelection(self, __a0: ghidra.program.util.ProgramSelection) -> None: ...

    def setStringContent(self, __a0: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

