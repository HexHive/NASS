import docking.action.builder
import ghidra.app.plugin.core.debug.gui
import ghidra.framework.plugintool
import java.lang


class DebuggerTrackLocationAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.TrackLocationAction, object):
    DESCRIPTION: unicode = u'Follow a location in this view'
    HELP_ANCHOR: unicode = u'track_location'
    ICON_NONE: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    ICON_PC: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    ICON_PC_BY_REGISTER: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    ICON_PC_BY_STACK: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    ICON_SP: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    NAME: unicode = u'Track Location'
    NAME_NONE: unicode = u'Do Not Track'
    NAME_PC: unicode = u'Track Program Counter'
    NAME_PC_BY_REGISTER: unicode = u'Track Program Counter (by Register)'
    NAME_PC_BY_STACK: unicode = u'Track Program Counter (by Stack)'
    NAME_PREFIX_WATCH: unicode = u'Track address of watch: '
    NAME_SP: unicode = u'Track Stack Pointer'







    @staticmethod
    def builder(__a0: ghidra.framework.plugintool.Plugin) -> docking.action.builder.MultiStateActionBuilder: ...

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

