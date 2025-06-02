import java.lang


class PayloadConstants(object):
    kBrilloMajorPayloadVersion: long = 0x2L
    kBrotliBsdiffMinorPayloadVersion: int = 4
    kChromeOSMajorPayloadVersion: long = 0x1L
    kDeltaMagic: unicode = u'CrAU'
    kFullPayloadMinorVersion: int = 0
    kInPlaceMinorPayloadVersion: int = 1
    kMaxPayloadHeaderSize: long = 0x18L
    kMaxSupportedMajorPayloadVersion: long = 0x2L
    kMaxSupportedMinorPayloadVersion: int = 6
    kMinSupportedMajorPayloadVersion: long = 0x1L
    kMinSupportedMinorPayloadVersion: int = 1
    kOpSrcHashMinorPayloadVersion: int = 3
    kPartitionNameKernel: unicode = u'kernel'
    kPartitionNameRoot: unicode = u'root'
    kPuffdiffMinorPayloadVersion: int = 5
    kSourceMinorPayloadVersion: int = 2
    kVerityMinorPayloadVersion: int = 6



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

