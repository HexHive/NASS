import docking
import ghidra.app.context
import ghidra.app.util.viewer.util
import java.awt
import java.awt.event
import java.lang


class DualDecompilerActionContext(docking.DefaultActionContext, ghidra.app.context.RestrictedAddressSetContext, ghidra.app.util.viewer.util.CodeComparisonPanelActionContext):
    """
    Action context for a dual decompiler panel.
    """





    def __init__(self, provider: docking.ComponentProvider, cPanel: ghidra.app.decompiler.component.CDisplayPanel, source: java.awt.Component):
        """
        Creates an action context for a dual decompiler panel.
        @param provider the provider for this context
        @param cPanel the decompiler panel associated with this context
        @param source the source of the action
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeComparisonPanel(self) -> ghidra.app.util.viewer.util.CodeComparisonPanel: ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getContextObject(self) -> object: ...

    def getEventClickModifiers(self) -> int: ...

    def getMouseEvent(self) -> java.awt.event.MouseEvent: ...

    def getSourceComponent(self) -> java.awt.Component: ...

    def getSourceObject(self) -> object: ...

    def hasAnyEventClickModifiers(self, modifiersMask: int) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setCodeComparisonPanel(self, codeComparisonPanel: ghidra.app.util.viewer.util.CodeComparisonPanel) -> None:
        """
        Sets the CodeComparisonPanel associated with this context.
        @param codeComparisonPanel the code comparison panel.
        """
        ...

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
    def codeComparisonPanel(self) -> ghidra.app.util.viewer.util.CodeComparisonPanel: ...

    @codeComparisonPanel.setter
    def codeComparisonPanel(self, value: ghidra.app.util.viewer.util.CodeComparisonPanel) -> None: ...