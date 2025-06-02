import java.lang


class MethodHandleType(object):
    kInstanceGet: int = 3
    kInstancePut: int = 2
    kInvokeConstructor: int = 6
    kInvokeDirect: int = 7
    kInvokeInstance: int = 5
    kInvokeInterface: int = 8
    kInvokeStatic: int = 4
    kLast: int = 8
    kStaticGet: int = 1
    kStaticPut: int = 0



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def toString(__a0: int) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

