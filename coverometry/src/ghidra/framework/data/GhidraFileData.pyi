import java.lang


class GhidraFileData(object):
    """
    GhidraFileData provides the managed object which represents a project file that 
     corresponds to matched FolderItem pair across both a versioned and private 
     filesystem and viewed as a single file at the project level.  This class closely mirrors the
     DomainFile interface and is used by the GhidraFile implementation; both of which
     represent immutable file references.  Changes made to this file's name or path are not reflected 
     in old DomainFile instances and must be re-instantiated following such a change.  
     Any long-term retention of DomainFolder and DomainFile instances requires an 
     appropriate change listener to properly discard/reacquire such instances.
    """

    CHECKED_OUT_EXCLUSIVE_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    CHECKED_OUT_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    HIJACKED_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    NOT_LATEST_CHECKED_OUT_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    READ_ONLY_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    UNSUPPORTED_FILE_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    VERSION_ICON: javax.swing.Icon = ghidra.framework.data.VersionIcon@442406e5







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

