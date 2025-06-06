import ghidra.app.plugin.core.script
import ghidra.app.script
import java.lang
import javax.swing
import javax.swing.event


class ScriptSelectionEditor(object):








    def addDocumentListener(self, __a0: javax.swing.event.DocumentListener) -> None: ...

    def addEditorListener(self, __a0: ghidra.app.plugin.core.script.ScriptEditorListener) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getEditorComponent(self) -> javax.swing.JComponent: ...

    def getEditorText(self) -> unicode: ...

    def getEditorValue(self) -> ghidra.app.script.ScriptInfo: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeDocumentListener(self, __a0: javax.swing.event.DocumentListener) -> None: ...

    def removeEditorListener(self, __a0: ghidra.app.plugin.core.script.ScriptEditorListener) -> None: ...

    def requestFocus(self) -> None: ...

    def setConsumeEnterKeyPress(self, __a0: bool) -> None: ...

    def toString(self) -> unicode: ...

    def validateUserSelection(self) -> bool: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def consumeEnterKeyPress(self) -> None: ...  # No getter available.

    @consumeEnterKeyPress.setter
    def consumeEnterKeyPress(self, value: bool) -> None: ...

    @property
    def editorComponent(self) -> javax.swing.JComponent: ...

    @property
    def editorText(self) -> unicode: ...

    @property
    def editorValue(self) -> ghidra.app.script.ScriptInfo: ...