from typing import List
import ghidra.feature.fid.db
import ghidra.program.model.lang
import java.io
import java.lang
import javax.swing.event


class FidFileManager(object):








    def addChangeListener(self, __a0: javax.swing.event.ChangeListener) -> None: ...

    def addUserFidFile(self, __a0: java.io.File) -> ghidra.feature.fid.db.FidFile: ...

    def canQuery(self, __a0: ghidra.program.model.lang.Language) -> bool: ...

    def createNewFidDatabase(self, __a0: java.io.File) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFidFiles(self) -> List[object]: ...

    @staticmethod
    def getInstance() -> ghidra.feature.fid.db.FidFileManager: ...

    def getUserAddedFiles(self) -> List[object]: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openFidQueryService(self, __a0: ghidra.program.model.lang.Language, __a1: bool) -> ghidra.feature.fid.db.FidQueryService: ...

    def removeChangeListener(self, __a0: javax.swing.event.ChangeListener) -> None: ...

    def removeUserFile(self, __a0: ghidra.feature.fid.db.FidFile) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def fidFiles(self) -> List[object]: ...

    @property
    def userAddedFiles(self) -> List[object]: ...