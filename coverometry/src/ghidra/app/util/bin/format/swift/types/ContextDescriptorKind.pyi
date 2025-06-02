import java.lang


class ContextDescriptorKind(object):
    """
    Swift ContextDescriptorKind values
    """

    ANONYMOUS: int = 2
    CLASS: int = 16
    ENUM: int = 18
    EXTENSION: int = 1
    MODULE: int = 0
    OPAQUE_TYPE: int = 4
    PROTOCOL: int = 3
    STRUCT: int = 17
    TYPE_FIRST: int = 16
    TYPE_LAST: int = 31



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getKind(flags: int) -> int:
        """
        Gets the {@link ContextDescriptorKind} value from the 
         {@link TargetContextDescriptor#getFlags() flags}
        @param flags The {@link TargetContextDescriptor#getFlags() flags} that contain the kind
        @return The {@link ContextDescriptorKind} value
        """
        ...

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

