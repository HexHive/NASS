import java.lang


class VerifyError(object):
    VERIFY_ERROR_ACCESS_CLASS: int = 32
    VERIFY_ERROR_ACCESS_FIELD: int = 64
    VERIFY_ERROR_ACCESS_METHOD: int = 128
    VERIFY_ERROR_BAD_CLASS_HARD: int = 1
    VERIFY_ERROR_BAD_CLASS_SOFT: int = 2
    VERIFY_ERROR_CLASS_CHANGE: int = 256
    VERIFY_ERROR_FORCE_INTERPRETER: int = 1024
    VERIFY_ERROR_INSTANTIATION: int = 512
    VERIFY_ERROR_LOCKING: int = 2048
    VERIFY_ERROR_NO_CLASS: int = 4
    VERIFY_ERROR_NO_FIELD: int = 8
    VERIFY_ERROR_NO_METHOD: int = 16
    VERIFY_ERROR_SKIP_COMPILER: int = -2147483648



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

