import java.lang


class MarkupStatusIcons(object):
    APPLIED_ADDED_ICON: javax.swing.Icon = MultiIcon[icon.version.tracking.markup.status.applied, jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png]
    APPLIED_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    APPLIED_REPLACED_ICON: javax.swing.Icon = MultiIcon[icon.version.tracking.markup.status.applied, jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png]
    APPLY_ADD_MENU_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    APPLY_REPLACE_MENU_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    CONFLICT_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    DONT_CARE_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    DONT_KNOW_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    FAILED_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    REJECTED_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    SAME_ICON: javax.swing.Icon = MultiIcon[icon.version.tracking.markup.status.applied, jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png]



    def __init__(self): ...



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

