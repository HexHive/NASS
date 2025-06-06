import docking.widgets.tree
import ghidra.framework.main.datatree
import ghidra.framework.plugintool
import java.awt.datatransfer
import java.awt.dnd
import java.lang


class JavaFileListHandler(ghidra.framework.main.datatree.AbstractFileListFlavorHandler):
    """
    A handler to facilitate drag-n-drop for a list of Java File objects which is dropped
     onto the Project data tree or a running Ghidra Tool (see DataFlavor#javaFileListFlavor).
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def handle(self, tool: ghidra.framework.plugintool.PluginTool, transferData: object, e: java.awt.dnd.DropTargetDropEvent, f: java.awt.datatransfer.DataFlavor) -> None: ...

    @overload
    def handle(self, tool: ghidra.framework.plugintool.PluginTool, dataTree: ghidra.framework.main.datatree.DataTree, destinationNode: docking.widgets.tree.GTreeNode, transferData: object, dropAction: int) -> None: ...

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

