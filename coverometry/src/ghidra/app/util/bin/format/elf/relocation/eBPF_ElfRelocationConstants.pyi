import java.lang


class eBPF_ElfRelocationConstants(object):
    R_BPF_64_32: int = 10
    R_BPF_64_64: int = 1
    R_BPF_64_ABS32: int = 3
    R_BPF_64_ABS64: int = 2
    R_BPF_64_NODYLD32: int = 4
    R_BPF_NONE: int = 0







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

