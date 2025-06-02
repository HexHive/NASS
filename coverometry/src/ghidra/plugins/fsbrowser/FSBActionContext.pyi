from typing import List
import docking
import docking.widgets.tree
import ghidra.formats.gfilesystem
import ghidra.plugins.fsbrowser
import java.awt
import java.awt.event
import java.lang


class FSBActionContext(docking.DefaultActionContext):
    """
    FileSystemBrowserPlugin-specific action.
    """





    def __init__(self, provider: ghidra.plugins.fsbrowser.FileSystemBrowserComponentProvider, selectedNodes: List[ghidra.plugins.fsbrowser.FSBNode], event: java.awt.event.MouseEvent, gTree: docking.widgets.tree.GTree):
        """
        Creates a new {@link FileSystemBrowserPlugin}-specific action context.
        @param provider the ComponentProvider that generated this context.
        @param selectedNodes selected nodes in the tree
        @param event MouseEvent that caused the update, or null
        @param gTree {@link FileSystemBrowserPlugin} provider tree.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getContextObject(self) -> object: ...

    def getEventClickModifiers(self) -> int: ...

    def getFSRL(self, dirsOk: bool) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the {@link FSRL} of the currently selected item, as long as it conforms to
         the dirsOk requirement.
        @param dirsOk boolean flag, if true the selected item can be either a file or directory
         element, if false, it must be a file or the root of a file system that has a container
         file
        @return FSRL of the single selected item, null if no items selected or more than 1 item
         selected
        """
        ...

    def getFSRLs(self, dirsOk: bool) -> List[ghidra.formats.gfilesystem.FSRL]:
        """
        Returns a list of FSRLs of the currently selected nodes in the tree.
        @param dirsOk boolean flag, if true the selected items can be either a file or directory
         element, if false, it must be a file or the root of a file system that has a container
         file before being included in the resulting list
        @return list of FSRLs of the currently selected items, maybe empty but never null
        """
        ...

    def getFileFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the FSRL of the currently selected file node
        @return FSRL of the currently selected file, or null if not file or more than 1 selected
        """
        ...

    def getFileFSRLs(self) -> List[ghidra.formats.gfilesystem.FSRL]:
        """
        Returns a list of FSRLs of the currently selected file nodes in the tree.
        @return list of FSRLs of the currently selected file items, maybe empty but never null
        """
        ...

    def getFormattedTreePath(self) -> unicode:
        """
        Converts the tree-node hierarchy of the currently selected item into a string path using
         "/" separators.
        @return string path of the currently selected tree item
        """
        ...

    def getLoadableFSRL(self) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the FSRL of the currently selected item, if it is a 'loadable' item.
        @return FSRL of the currently selected loadable item, or null if nothing selected or
         more than 1 selected
        """
        ...

    def getLoadableFSRLs(self) -> List[ghidra.formats.gfilesystem.FSRL]:
        """
        Returns a list of FSRLs of the currently selected loadable items.
        @return list of FSRLs of currently selected loadable items, maybe empty but never null
        """
        ...

    def getMouseEvent(self) -> java.awt.event.MouseEvent: ...

    def getRootOfSelectedNode(self) -> ghidra.plugins.fsbrowser.FSBRootNode:
        """
        Returns the FSBRootNode that contains the currently selected tree node.
        @return FSBRootNode that contains the currently selected tree node, or null nothing
         selected
        """
        ...

    def getSelectedCount(self) -> int:
        """
        Returns the number of selected nodes in the tree.
        @return returns the number of selected nodes in the tree.
        """
        ...

    def getSelectedNode(self) -> ghidra.plugins.fsbrowser.FSBNode:
        """
        Returns the currently selected tree node
        @return the currently selected tree node, or null if no nodes or more than 1 node is selected
        """
        ...

    def getSelectedNodes(self) -> List[ghidra.plugins.fsbrowser.FSBNode]:
        """
        Returns a list of the currently selected tree nodes.
        @return list of currently selected tree nodes
        """
        ...

    def getSourceComponent(self) -> java.awt.Component: ...

    def getSourceObject(self) -> object: ...

    def getTree(self) -> docking.widgets.tree.GTree:
        """
        Gets the {@link FileSystemBrowserPlugin} provider's  tree.
        @return The {@link FileSystemBrowserPlugin} provider's  tree.
        """
        ...

    def hasAnyEventClickModifiers(self, modifiersMask: int) -> bool: ...

    def hasSelectedNodes(self) -> bool:
        """
        Returns true if there are selected nodes in the browser tree.
        @return boolean true if there are selected nodes in the browser tree
        """
        ...

    def hashCode(self) -> int: ...

    def isBusy(self) -> bool:
        """
        Returns true if the GTree is busy
        @return boolean true if the GTree is busy
        """
        ...

    def isSelectedAllDirs(self) -> bool:
        """
        Returns true if the currently selected items are all directory items
        @return boolean true if the currently selected items are all directory items
        """
        ...

    def notBusy(self) -> bool:
        """
        Returns true if the GTree is not busy
        @return boolean true if GTree is not busy
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setContextObject(self, contextObject: object) -> docking.DefaultActionContext: ...

    def setEventClickModifiers(self, modifiers: int) -> None: ...

    def setMouseEvent(self, e: java.awt.event.MouseEvent) -> docking.DefaultActionContext: ...

    def setSourceObject(self, sourceObject: object) -> docking.DefaultActionContext: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def busy(self) -> bool: ...

    @property
    def fileFSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    @property
    def fileFSRLs(self) -> List[object]: ...

    @property
    def formattedTreePath(self) -> unicode: ...

    @property
    def loadableFSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    @property
    def loadableFSRLs(self) -> List[object]: ...

    @property
    def rootOfSelectedNode(self) -> ghidra.plugins.fsbrowser.FSBRootNode: ...

    @property
    def selectedAllDirs(self) -> bool: ...

    @property
    def selectedCount(self) -> int: ...

    @property
    def selectedNode(self) -> ghidra.plugins.fsbrowser.FSBNode: ...

    @property
    def selectedNodes(self) -> List[object]: ...

    @property
    def tree(self) -> docking.widgets.tree.GTree: ...