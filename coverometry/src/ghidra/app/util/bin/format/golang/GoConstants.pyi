import java.lang


class GoConstants(object):
    """
    Misc constant values for golang
    """

    GOLANG_ABI0_CALLINGCONVENTION_NAME: unicode = u'abi0'
    GOLANG_ABI_INTERNAL_CALLINGCONVENTION_NAME: unicode = u'abi-internal'
    GOLANG_CATEGORYPATH: ghidra.program.model.data.CategoryPath = /golang
    GOLANG_CSPEC_NAME: unicode = u'golang'
    GOLANG_DUFFCOPY_CALLINGCONVENTION_NAME: unicode = u'duffcopy'
    GOLANG_DUFFZERO_CALLINGCONVENTION_NAME: unicode = u'duffzero'



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

