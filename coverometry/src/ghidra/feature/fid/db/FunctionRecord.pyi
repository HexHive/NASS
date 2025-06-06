import ghidra.feature.fid.db
import ghidra.feature.fid.hash
import ghidra.program.database
import ghidra.util
import java.lang


class FunctionRecord(ghidra.program.database.DatabaseObject, ghidra.feature.fid.hash.FidHashQuad):
    AUTO_FAIL_FLAG: int = 4
    AUTO_PASS_FLAG: int = 2
    FORCE_RELATION_FLAG: int = 16
    FORCE_SPECIFIC_FLAG: int = 8
    HAS_TERMINATOR_FLAG: int = 1







    def autoFail(self) -> bool: ...

    def autoPass(self) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeUnitSize(self) -> int: ...

    def getDomainPath(self) -> unicode: ...

    def getEntryPoint(self) -> long: ...

    def getFidDb(self) -> ghidra.feature.fid.db.FidDB: ...

    def getFullHash(self) -> long: ...

    def getID(self) -> long: ...

    def getKey(self) -> long: ...

    def getLibraryID(self) -> long: ...

    def getName(self) -> unicode: ...

    def getSpecificHash(self) -> long: ...

    def getSpecificHashAdditionalSize(self) -> int: ...

    def hasTerminator(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isDeleted(self, __a0: ghidra.util.Lock) -> bool: ...

    def isForceRelation(self) -> bool: ...

    def isForceSpecific(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setInvalid(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def ID(self) -> long: ...

    @property
    def codeUnitSize(self) -> int: ...

    @property
    def domainPath(self) -> unicode: ...

    @property
    def entryPoint(self) -> long: ...

    @property
    def fidDb(self) -> ghidra.feature.fid.db.FidDB: ...

    @property
    def forceRelation(self) -> bool: ...

    @property
    def forceSpecific(self) -> bool: ...

    @property
    def fullHash(self) -> long: ...

    @property
    def libraryID(self) -> long: ...

    @property
    def name(self) -> unicode: ...

    @property
    def specificHash(self) -> long: ...

    @property
    def specificHashAdditionalSize(self) -> int: ...