from typing import List
import docking.widgets.fieldpanel.field
import ghidra.app.nav
import ghidra.app.util.viewer.field
import ghidra.framework.plugintool
import ghidra.program.model.listing
import java.lang


class SymbolAnnotatedStringHandler(object, ghidra.app.util.viewer.field.AnnotatedStringHandler):
    """
    An annotated string handler that handles annotations that begin with
     #SUPPORTED_ANNOTATIONS.  This class expects one string following the annotation
     text that is the address or a symbol name.  The display text will be that of the symbol that
     is referred to by the address or symbol name.
    """

    DUMMY_MOUSE_HANDLER: ghidra.app.util.viewer.field.AnnotatedMouseHandler = ghidra.app.util.viewer.field.AnnotatedStringHandler$1@420aec69



    def __init__(self): ...



    @staticmethod
    def convertAnnotationSymbolToAddress(annotationParts: List[unicode], rawText: unicode, program: ghidra.program.model.listing.Program) -> unicode: ...

    def createAnnotatedString(self, prototypeString: docking.widgets.fieldpanel.field.AttributedString, text: List[unicode], program: ghidra.program.model.listing.Program) -> docking.widgets.fieldpanel.field.AttributedString: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisplayString(self) -> unicode: ...

    @overload
    def getPrototypeString(self) -> unicode: ...

    @overload
    def getPrototypeString(self, displayText: unicode) -> unicode: ...

    def getSupportedAnnotations(self) -> List[unicode]: ...

    def handleMouseClick(self, annotationParts: List[unicode], sourceNavigatable: ghidra.app.nav.Navigatable, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> bool: ...

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