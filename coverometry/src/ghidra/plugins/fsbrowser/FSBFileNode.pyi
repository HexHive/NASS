from typing import Iterator
from typing import List
import docking.widgets.tree
import docking.widgets.tree.support
import ghidra.formats.gfilesystem
import ghidra.plugins.fsbrowser
import ghidra.util.task
import java.lang
import java.util.function
import java.util.stream
import javax.swing
import javax.swing.tree


class FSBFileNode(ghidra.plugins.fsbrowser.FSBNode):
    """
    GTreeNode that represents a file on a filesystem.
    """









    @overload
    def addNode(self, node: docking.widgets.tree.GTreeNode) -> None: ...

    @overload
    def addNode(self, index: int, node: docking.widgets.tree.GTreeNode) -> None: ...

    def addNodes(self, __a0: List[object]) -> None: ...

    def clone(self) -> docking.widgets.tree.GTreeNode:
        """
        Creates a clone of this node.  The clone should contain a shallow copy of all the node's
         attributes except that the parent and children are null.
        @return the clone of this object.
        @throws CloneNotSupportedException if some implementation prevents itself from being cloned.
        """
        ...

    def collapse(self) -> None:
        """
        Convenience method for collapsing (closing) this node in the tree. If this node is not
         currently attached to a visible tree, then this call does nothing
        """
        ...

    @overload
    def compareTo(self, node: docking.widgets.tree.GTreeNode) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    @staticmethod
    def createNodeFromFile(file: ghidra.formats.gfilesystem.GFile) -> ghidra.plugins.fsbrowser.FSBFileNode:
        """
        Helper method to convert a single {@link GFile} object into a FSBNode object.
        @param file {@link GFile} to convert
        @return a new {@link FSBFileNode} with type specific to the GFile's type.
        """
        ...

    @staticmethod
    def createNodesFromFileList(__a0: List[object], __a1: ghidra.util.task.TaskMonitor) -> List[object]: ...

    def dispose(self) -> None: ...

    def equals(self, obj: object) -> bool: ...

    def expand(self) -> None:
        """
        Convenience method for expanding (opening) this node in the tree. If this node is not
         currently attached to a visible tree, then this call does nothing
        """
        ...

    def filter(self, filter: docking.widgets.tree.support.GTreeFilter, monitor: ghidra.util.task.TaskMonitor) -> docking.widgets.tree.GTreeNode:
        """
        Generates a filtered copy of this node and its children.
         <P>
         A node will be included if it or any of its descendants are accepted by the filter. NOTE: the
         filter will only be applied to a nodes children if they are loaded. So to perform a filter on
         all the nodes in the tree, the {@link #loadAll(TaskMonitor)} should be called before the
         filter call.
        @param filter the filter being applied
        @param monitor a TaskMonitor for tracking the progress and cancelling
        @return A copy of this node and its children that matches the filter or null if this node and
                 none of its children match the filter.
        @throws CancelledException if the operation is cancelled via the TaskMonitor
        @throws CloneNotSupportedException if any nodes in the tree explicitly prevents cloning
        """
        ...

    @staticmethod
    def findContainingFileSystemFSBRootNode(node: ghidra.plugins.fsbrowser.FSBNode) -> ghidra.plugins.fsbrowser.FSBRootNode:
        """
        Returns the {@link FSBRootNode} that represents the root of the file system that
         contains the specified file node.
        @param node GTree node that represents a file.
        @return FSBRootNode that represents the file system holding the file.
        """
        ...

    def fireNodeChanged(self) -> None:
        """
        Notifies the tree that a node has changed, excluding its children. If it has gained or lost
         children, then use {@link #fireNodeStructureChanged()} instead.
        """
        ...

    def fireNodeStructureChanged(self) -> None:
        """
        Notifies the tree that the node has different children.
        """
        ...

    def generateChildren(self, monitor: ghidra.util.task.TaskMonitor) -> List[docking.widgets.tree.GTreeNode]: ...

    @overload
    def getChild(self, index: int) -> docking.widgets.tree.GTreeNode:
        """
        Returns the child node at the given index. Returns null if the index is out of bounds.
        @param index the index of the child to be returned
        @return the child at the given index
        """
        ...

    @overload
    def getChild(self, name: unicode) -> docking.widgets.tree.GTreeNode:
        """
        Returns the child node of this node with the given name.
        @param name the name of the child to be returned
        @return the child with the given name
        """
        ...

    @overload
    def getChild(self, name: unicode, filter: java.util.function.Predicate) -> docking.widgets.tree.GTreeNode:
        """
        Returns the child node of this node with the given name which satisfies predicate filter.
        @param name the name of the child to be returned
        @param filter predicate filter
        @return the child with the given name
        """
        ...

    def getChildCount(self) -> int:
        """
        Returns the number of <b>visible</b> children of this node. Does not include nodes that are
         current filtered out
        @return the number of <b>visible</b> children of this node
        """
        ...

    def getChildren(self) -> List[docking.widgets.tree.GTreeNode]:
        """
        Returns all of the <b>visible</b> children of this node. If there are filtered nodes, then
         they will not be returned.
        @return all of the <b>visible</b> children of this node. If there are filtered nodes, then
                 they will not be returned.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDisplayText(self) -> unicode:
        """
        Returns the display text for the node. By default, this is the same as the name of the node.
         The name of the node usually serves two purposes: 1) to uniquely identify the node (the
         identity) and 2) the display text (what you see in the tree). Sometimes, it is useful to
         display more information in the tree without affecting the nodes identity. In this case, you
         can override this method to return the "display" name, while {@link #getName()} will still
         return the name used to identify the node.
        @return the display text for the node.
        """
        ...

    def getFSBRootNode(self) -> ghidra.plugins.fsbrowser.FSBRootNode: ...

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    def getIcon(self, expanded: bool) -> javax.swing.Icon: ...

    def getIndexInParent(self) -> int:
        """
        Returns the index of this node within its parent node
        @return the index of this node within its parent node
        """
        ...

    def getIndexOfChild(self, node: docking.widgets.tree.GTreeNode) -> int:
        """
        Returns the index of the given node within this node. -1 is returned if the node is not a
         child of this node.
        @param node whose index we want
        @return the index of the given node within this node
        """
        ...

    def getLeafCount(self) -> int:
        """
        Returns the total number of leaf nodes in the subtree from this node. Note that if any nodes
         are "lazy" (see {@link GTreeLazyNode}) and not currently loaded, then it will be considered
         as a leaf and return 1.
        @return the total number of leaf nodes in the subtree from this node
        """
        ...

    def getName(self) -> unicode: ...

    def getNodeCount(self) -> int:
        """
        Returns the total number of nodes in the subtree rooted at this node. Leaf nodes return 1.
        @return the number of nodes from this node downward
        """
        ...

    def getParent(self) -> docking.widgets.tree.GTreeNode:
        """
        Returns the parent of this node.
 
         Note: this method is deliberately not synchronized (See comments above)
        @return the parent of this node.
        """
        ...

    def getRoot(self) -> docking.widgets.tree.GTreeNode:
        """
        Returns the rootNode for this tree or null if there is no parent path to a root node.
        @return the rootNode for a tree of nodes in a {@link GTree}
        """
        ...

    def getToolTip(self) -> unicode: ...

    def getTree(self) -> docking.widgets.tree.GTree:
        """
        Returns the GTree that this node is attached to
        @return the GTree that this node is attached to
        """
        ...

    def getTreePath(self) -> javax.swing.tree.TreePath:
        """
        Returns the TreePath for this node
        @return the TreePath for this node
        """
        ...

    def hasMissingPassword(self) -> bool:
        """
        Returns true if this file is missing its password
        @return boolean true if this file is missing its password
        """
        ...

    def hasPassword(self) -> bool:
        """
        Local copy of the original GFile's {@link FileAttributeType#HAS_GOOD_PASSWORD_ATTR} attribute.
        @return boolean true if a password for the file has been found, false if missing the password
        """
        ...

    def hashCode(self) -> int: ...

    def isAncestor(self, node: docking.widgets.tree.GTreeNode) -> bool:
        """
        Returns true if the given node is a child of this node or one of its children.
        @param node the potential descendant node to check
        @return true if the given node is a child of this node or one of its children
        """
        ...

    def isAutoExpandPermitted(self) -> bool:
        """
        Determine if this node may be auto-expanded.  Some special node cases may need to prevent
         or limit auto-expansion due to tree depth or other special conditions.
        @return true if this node allows auto-expansion, else false.
        """
        ...

    def isEditable(self) -> bool:
        """
        Returns true if this node is allowed to be edited in the tree. You must override this method
         to allow a node to be edited. You must also override {@link #valueChanged(Object)} to handle
         the result of the edit.
        @return true if this node is allowed to be edited in the tree
        @see #valueChanged(Object)
        """
        ...

    def isEncrypted(self) -> bool:
        """
        Local copy of the original GFile's {@link FileAttributeType#IS_ENCRYPTED_ATTR} attribute.
        @return boolean true if file needs a password to be read
        """
        ...

    def isExpanded(self) -> bool:
        """
        Convenience method determining if this node is expanded in a tree. If the node is not
         currently attached to a visible tree, then this call returns false
        @return true if the node is expanded in a currently visible tree.
        """
        ...

    def isInProgress(self) -> bool:
        """
        Returns true if the node is in the process of loading its children. 
         See {@link GTreeSlowLoadingNode}
        @return true if the node is in the process of loading its children.
        """
        ...

    def isLeaf(self) -> bool: ...

    def isLoaded(self) -> bool:
        """
        True if the children for this node have been loaded yet.  Some GTree nodes are lazy in that they
         don't load their children until needed. Nodes that have the IN_PROGRESS node as it child
         is considered loaded if in the swing thread, otherwise they are considered not loaded.
        @return true if the children for this node have been loaded.
        """
        ...

    def isRoot(self) -> bool:
        """
        Returns true if this is a root node of a GTree
        @return true if this is a root node of a GTree
        """
        ...

    def iterator(self, depthFirst: bool) -> Iterator[docking.widgets.tree.GTreeNode]:
        """
        Returns an iterator of the GTree nodes in the subtree of this node
        @param depthFirst if true, the nodes will be returned in depth-first order, otherwise
                    breadth-first order
        @return an iterator of the GTree nodes in the subtree of this node
        """
        ...

    def loadAll(self, monitor: ghidra.util.task.TaskMonitor) -> int: ...

    def needsFileAttributesUpdate(self, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Returns true if this node's password status has changed, calling for a complete refresh
         of the status of all files in the file system.
        @param monitor {@link TaskMonitor}
        @return boolean true if this nodes password status has changed
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeAll(self) -> None: ...

    def removeNode(self, node: docking.widgets.tree.GTreeNode) -> None: ...

    def setChildren(self, __a0: List[object]) -> None: ...

    def stream(self, depthFirst: bool) -> java.util.stream.Stream:
        """
        Returns a stream of the GTree nodes in the subtree of this node
        @param depthFirst if true, the nodes will be streamed in depth-first order, otherwise
                    breadth-first order
        @return a stream of the GTree nodes in the subtree of this node
        """
        ...

    def toString(self) -> unicode: ...

    def unloadChildren(self) -> None:
        """
        Sets this lazy node back to the "unloaded" state such that if
         its children are accessed, it will reload its children as needed.
        """
        ...

    def valueChanged(self, newValue: object) -> None:
        """
        Notification method called when a cell editor completes editing to notify this node that its
         value has changed. If you override this method you must also override {@link #isEditable()}.
        @param newValue the new value provided by the cell editor
        @see #isEditable()
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def FSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    @property
    def encrypted(self) -> bool: ...

    @property
    def leaf(self) -> bool: ...