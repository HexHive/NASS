from typing import List
import docking.dnd
import java.awt.datatransfer
import java.io
import java.lang


class SymbolTreeDataFlavor(docking.dnd.GenericDataFlavor):
    DATA_FLAVOR: java.awt.datatransfer.DataFlavor = ghidra.app.plugin.core.symboltree.nodes.SymbolTreeDataFlavor[mimetype=application/x-java-jvm-local-objectref;representationclass=ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode]



    def __init__(self, __a0: unicode): ...



    def clone(self) -> object: ...

    @overload
    def equals(self, __a0: unicode) -> bool: ...

    @overload
    def equals(self, __a0: java.awt.datatransfer.DataFlavor) -> bool: ...

    @overload
    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultRepresentationClass(self) -> java.lang.Class: ...

    def getDefaultRepresentationClassAsString(self) -> unicode: ...

    def getHumanPresentableName(self) -> unicode: ...

    def getMimeType(self) -> unicode: ...

    def getParameter(self, __a0: unicode) -> unicode: ...

    def getPrimaryType(self) -> unicode: ...

    def getReaderForText(self, __a0: java.awt.datatransfer.Transferable) -> java.io.Reader: ...

    def getRepresentationClass(self) -> java.lang.Class: ...

    def getSubType(self) -> unicode: ...

    @staticmethod
    def getTextPlainUnicodeFlavor() -> java.awt.datatransfer.DataFlavor: ...

    def hashCode(self) -> int: ...

    def isFlavorJavaFileListType(self) -> bool: ...

    def isFlavorRemoteObjectType(self) -> bool: ...

    def isFlavorSerializedObjectType(self) -> bool: ...

    def isFlavorTextType(self) -> bool: ...

    @overload
    def isMimeTypeEqual(self, __a0: unicode) -> bool: ...

    @overload
    def isMimeTypeEqual(self, __a0: java.awt.datatransfer.DataFlavor) -> bool: ...

    def isMimeTypeSerializedObject(self) -> bool: ...

    def isRepresentationClassByteBuffer(self) -> bool: ...

    def isRepresentationClassCharBuffer(self) -> bool: ...

    def isRepresentationClassInputStream(self) -> bool: ...

    def isRepresentationClassReader(self) -> bool: ...

    def isRepresentationClassRemote(self) -> bool: ...

    def isRepresentationClassSerializable(self) -> bool: ...

    def match(self, __a0: java.awt.datatransfer.DataFlavor) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readExternal(self, __a0: java.io.ObjectInput) -> None: ...

    @staticmethod
    def selectBestTextFlavor(__a0: List[java.awt.datatransfer.DataFlavor]) -> java.awt.datatransfer.DataFlavor: ...

    def setHumanPresentableName(self, __a0: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeExternal(self, __a0: java.io.ObjectOutput) -> None: ...

