from typing import List
import ghidra.xml
import java.lang


class AbstractXmlPullParser(object, ghidra.xml.XmlPullParser):




    def __init__(self): ...



    @overload
    def discardSubTree(self) -> int: ...

    @overload
    def discardSubTree(self, elementName: unicode) -> int: ...

    @overload
    def discardSubTree(self, element: ghidra.xml.XmlElement) -> int: ...

    def dispose(self) -> None: ...

    @overload
    def end(self) -> ghidra.xml.XmlElement: ...

    @overload
    def end(self, element: ghidra.xml.XmlElement) -> ghidra.xml.XmlElement: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getColumnNumber(self) -> int: ...

    def getCurrentLevel(self) -> int: ...

    def getLineNumber(self) -> int: ...

    def getName(self) -> unicode: ...

    def getProcessingInstruction(self, __a0: unicode, __a1: unicode) -> unicode: ...

    def hasNext(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isPullingContent(self) -> bool: ...

    def next(self) -> ghidra.xml.XmlElement: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def peek(self) -> ghidra.xml.XmlElement: ...

    def setPullingContent(self, __a0: bool) -> None: ...

    def softStart(self, names: List[unicode]) -> ghidra.xml.XmlElement: ...

    def start(self, names: List[unicode]) -> ghidra.xml.XmlElement: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def columnNumber(self) -> int: ...

    @property
    def currentLevel(self) -> int: ...

    @property
    def lineNumber(self) -> int: ...

    @property
    def name(self) -> unicode: ...

    @property
    def pullingContent(self) -> bool: ...

    @pullingContent.setter
    def pullingContent(self, value: bool) -> None: ...