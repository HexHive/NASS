import ghidra.program.model.listing
import java.lang


class FBPK_Constants(object):
    FBPK: unicode = u'FBPK'
    FBPK_MAGIC: int = 1263551046
    FBPT: unicode = u'FBPT'
    FBPT_MAGIC: int = 1414545990
    NAME_MAX_LENGTH: int = 36
    PARTITION_TABLE: unicode = u'partition table'
    PARTITION_TYPE_DIRECTORY: int = 0
    PARTITION_TYPE_FILE: int = 1
    UFPK: unicode = u'UFPK'
    UFPK_MAGIC: int = 1263552085
    UFSM: unicode = u'UFSM'
    UFSM_MAGIC: int = 1297303125
    UFSP: unicode = u'UFSP'
    UFSP_MAGIC: int = 1347634773
    V1_LAST_PARTITION_ENTRY: unicode = u'last_parti'
    V1_PADDING_LENGTH: int = 2
    V1_VERSION_MAX_LENGTH: int = 68
    V2_FORMAT_MAX_LENGTH: int = 14
    V2_GUID_MAX_LENGTH: int = 44
    V2_PARTITION: unicode = u'partition:'
    V2_PARTITION_NAME_MAX_LENGTH: int = 76
    V2_STRING1_MAX_LENGTH: int = 16
    V2_STRING2_MAX_LENGTH: int = 68
    V2_UFPK_STRING1_MAX_LENGTH: int = 76
    V2_UFS: unicode = u'ufs'
    V2_UFSFWUPDATE: object = u'ufsfwupdate'
    VERSION_1: int = 1
    VERSION_2: int = 2



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isFBPK(__a0: ghidra.program.model.listing.Program) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

