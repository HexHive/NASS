import docking.widgets.tree
import ghidra.app.util
import ghidra.framework.main.datatree
import ghidra.framework.plugintool
import java.awt.datatransfer
import java.awt.dnd
import java.lang


class AbstractFileListFlavorHandler(object, ghidra.framework.main.datatree.DataTreeFlavorHandler, ghidra.app.util.FileOpenDataFlavorHandler):
    """
    An abstract handler to facilitate drag-n-drop for a list of Java File objects which is 
     dropped onto the Project data tree (see DataTreeFlavorHandler) or a running Ghidra Tool
     (see FileOpenDataFlavorHandler).
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def handle(self, __a0: ghidra.framework.plugintool.PluginTool, __a1: object, __a2: java.awt.dnd.DropTargetDropEvent, __a3: java.awt.datatransfer.DataFlavor) -> None: ...

    @overload
    def handle(self, __a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.framework.main.datatree.DataTree, __a2: docking.widgets.tree.GTreeNode, __a3: object, __a4: int) -> None: ...

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

