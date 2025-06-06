import java.lang


class JavaSourceLine(object):




    def __init__(self, line: unicode, lineNumber: int): ...



    def append(self, text: unicode) -> None: ...

    def delete(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLeadingWhitespace(self) -> unicode: ...

    def getLineNumber(self) -> int: ...

    def getOriginalText(self) -> unicode: ...

    def getText(self) -> unicode: ...

    def hasChanges(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isDeleted(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def prepend(self, text: unicode) -> None: ...

    def setText(self, text: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def deleted(self) -> bool: ...

    @property
    def leadingWhitespace(self) -> unicode: ...

    @property
    def lineNumber(self) -> int: ...

    @property
    def originalText(self) -> unicode: ...

    @property
    def text(self) -> unicode: ...

    @text.setter
    def text(self, value: unicode) -> None: ...