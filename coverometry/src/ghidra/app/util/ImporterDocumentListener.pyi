import java.lang
import javax.swing.event


class ImporterDocumentListener(object, javax.swing.event.DocumentListener):








    def changedUpdate(self, e: javax.swing.event.DocumentEvent) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def insertUpdate(self, e: javax.swing.event.DocumentEvent) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeUpdate(self, e: javax.swing.event.DocumentEvent) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

