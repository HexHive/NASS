import ghidra.app.plugin.core.datamgr.archive
import ghidra.program.model.data
import ghidra.util
import java.awt
import java.lang
import javax.swing


class InvalidFileArchive(object, ghidra.app.plugin.core.datamgr.archive.Archive):








    def close(self) -> None: ...

    @overload
    def compareTo(self, __a0: ghidra.app.plugin.core.datamgr.archive.Archive) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getArchiveType(self) -> ghidra.program.model.data.ArchiveType: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    def getDomainFileID(self) -> unicode: ...

    def getIcon(self, __a0: bool) -> javax.swing.Icon: ...

    def getName(self) -> unicode: ...

    def getUniversalID(self) -> ghidra.util.UniversalID: ...

    def hashCode(self) -> int: ...

    def isChanged(self) -> bool: ...

    def isModifiable(self) -> bool: ...

    def isSavable(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def save(self) -> None: ...

    def saveAs(self, __a0: java.awt.Component) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def archiveType(self) -> ghidra.program.model.data.ArchiveType: ...

    @property
    def changed(self) -> bool: ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def domainFileID(self) -> unicode: ...

    @property
    def modifiable(self) -> bool: ...

    @property
    def name(self) -> unicode: ...

    @property
    def savable(self) -> bool: ...

    @property
    def universalID(self) -> ghidra.util.UniversalID: ...