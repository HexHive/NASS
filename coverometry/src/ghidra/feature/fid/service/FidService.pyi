from typing import List
import ghidra.feature.fid.db
import ghidra.feature.fid.hash
import ghidra.feature.fid.service
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.util.task
import java.lang
import java.util.function


class FidService(object):
    MEDIUM_HASH_CODE_UNIT_LENGTH: int = 24
    MULTINAME_SCORE_THRESHOLD: float = 30.0
    SCORE_THRESHOLD: float = 14.600000381469727
    SHORT_HASH_CODE_UNIT_LENGTH: int = 4



    def __init__(self): ...



    def canProcess(self, __a0: ghidra.program.model.lang.Language) -> bool: ...

    def createNewLibraryFromPrograms(self, __a0: ghidra.feature.fid.db.FidDB, __a1: unicode, __a2: unicode, __a3: unicode, __a4: List[object], __a5: java.util.function.Predicate, __a6: ghidra.program.model.lang.LanguageID, __a7: List[object], __a8: List[object], __a9: ghidra.util.task.TaskMonitor) -> ghidra.feature.fid.service.FidPopulateResult: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultMultiNameThreshold(self) -> float: ...

    def getDefaultScoreThreshold(self) -> float: ...

    def getHasher(self, __a0: ghidra.program.model.listing.Program) -> ghidra.feature.fid.hash.FidHasher: ...

    def getMediumHashCodeUnitLengthLimit(self) -> int: ...

    def getProgramSeeker(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.feature.fid.db.FidQueryService, __a2: float) -> ghidra.feature.fid.service.FidProgramSeeker: ...

    def getShortHashCodeUnitLength(self) -> int: ...

    def hashCode(self) -> int: ...

    def hashFunction(self, __a0: ghidra.program.model.listing.Function) -> ghidra.feature.fid.hash.FidHashQuad: ...

    def markRecordsAutoFail(self, __a0: List[object], __a1: bool) -> List[object]: ...

    def markRecordsAutoPass(self, __a0: List[object], __a1: bool) -> List[object]: ...

    def markRecordsForceRelation(self, __a0: List[object], __a1: bool) -> List[object]: ...

    def markRecordsForceSpecific(self, __a0: List[object], __a1: bool) -> List[object]: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openFidQueryService(self, __a0: ghidra.program.model.lang.Language, __a1: bool) -> ghidra.feature.fid.db.FidQueryService: ...

    def processProgram(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.feature.fid.db.FidQueryService, __a2: float, __a3: ghidra.util.task.TaskMonitor) -> List[object]: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def defaultMultiNameThreshold(self) -> float: ...

    @property
    def defaultScoreThreshold(self) -> float: ...

    @property
    def mediumHashCodeUnitLengthLimit(self) -> int: ...

    @property
    def shortHashCodeUnitLength(self) -> int: ...