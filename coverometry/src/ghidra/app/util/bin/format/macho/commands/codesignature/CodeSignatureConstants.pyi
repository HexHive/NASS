import java.lang


class CodeSignatureConstants(object):
    """
    Code Signature constants
    """

    CSMAGIC_BLOBWRAPPER: int = -86111487
    CSMAGIC_CODEDIRECTORY: int = -86111230
    CSMAGIC_DETACHED_SIGNATURE: int = -86111039
    CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: int = -86085262
    CSMAGIC_EMBEDDED_ENTITLEMENTS: int = -86085263
    CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT: int = -86081151
    CSMAGIC_EMBEDDED_SIGNATURE: int = -86111040
    CSMAGIC_EMBEDDED_SIGNATURE_OLD: int = -86111486
    CSMAGIC_REQUIREMENT: int = -86111232
    CSMAGIC_REQUIREMENTS: int = -86111231



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

