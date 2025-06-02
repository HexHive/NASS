import docking.action.builder
import ghidra.app.plugin.core.debug.gui
import ghidra.framework.plugintool
import java.lang


class DebuggerAutoReadMemoryAction(ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction, object):
    DESCRIPTION: unicode = u'Automatically read and record visible memory from the live target'
    HELP_ANCHOR: unicode = u'auto_memory'
    ICON_LOAD_EMU: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    ICON_NONE: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    ICON_VISIBLE: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    ICON_VIS_RO_ONCE: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    NAME: unicode = u'Auto-Read Target Memory'
    NAME_LOAD_EMU: unicode = u'Load Emulator from Programs'
    NAME_NONE: unicode = u'Do Not Read Memory'
    NAME_VISIBLE: unicode = u'Read Visible Memory'
    NAME_VIS_RO_ONCE: unicode = u'Read Visible Memory, RO Once'







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

