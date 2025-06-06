from typing import List
import docking.widgets.fieldpanel.field
import ghidra.app.nav
import ghidra.app.util.viewer.field
import ghidra.framework.plugintool
import ghidra.program.model.listing
import java.lang


class InvalidAnnotatedStringHandler(object, ghidra.app.util.viewer.field.AnnotatedStringHandler):
    """
    An annotated string handler that is used to display an error message string when there is a
     problem creating an annotated string.
    """

    DUMMY_MOUSE_HANDLER: ghidra.app.util.viewer.field.AnnotatedMouseHandler = ghidra.app.util.viewer.field.AnnotatedStringHandler$1@420aec69



    @overload
    def __init__(self): ...

    @overload
    def __init__(self, errorText: unicode): ...



    def createAnnotatedString(self, prototypeString: docking.widgets.fieldpanel.field.AttributedString, text: List[unicode], program: ghidra.program.model.listing.Program) -> docking.widgets.fieldpanel.field.AttributedString: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisplayString(self) -> unicode: ...

    @overload
    def getPrototypeString(self) -> unicode: ...

    @overload
    def getPrototypeString(self, displayText: unicode) -> unicode: ...

    def getSupportedAnnotations(self) -> List[unicode]: ...

    def handleMouseClick(self, annotationParts: List[unicode], navigatable: ghidra.app.nav.Navigatable, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> bool: ...

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

    @property
    def displayString(self) -> unicode: ...

    @property
    def prototypeString(self) -> unicode: ...

    @property
    def supportedAnnotations(self) -> List[unicode]: ...