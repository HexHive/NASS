import java.lang


class OldVariableStorageDBAdapterV0V1(object):
    """
    OldVariableStorageDBAdapterV0V1 provide legacy variable storage 
     table support where each variable storage record was namespace-specific and
     provided storage address only.  In a later revision this was deemed inadequate 
     since size information and support for storage binding was needed.
    """





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

