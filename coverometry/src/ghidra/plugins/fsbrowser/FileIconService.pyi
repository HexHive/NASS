from typing import List
import ghidra.plugins.fsbrowser
import java.lang
import javax.swing


class FileIconService(object):
    """
    Provides Icons that represent the type and status of a file, based on
     a filename mapping and caller specified status overlays.
 
     The mappings between a file's extension and its icon are stored in a resource
     file called "file_extension_icons.xml", which is read and parsed the first
     time this service is referenced.
 
     Status overlays are also specified in the file_extension_icons.xml file, and
     are resized to be 1/2 the width and height of the icon they are being
     overlaid on.
 
     Thread safe
 
    """

    DEFAULT_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    FILESYSTEM_OVERLAY_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    IMPORTED_OVERLAY_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    MISSING_PASSWORD_OVERLAY_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getIcon(self, __a0: unicode, __a1: List[object]) -> javax.swing.Icon: ...

    @staticmethod
    def getInstance() -> ghidra.plugins.fsbrowser.FileIconService: ...

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

