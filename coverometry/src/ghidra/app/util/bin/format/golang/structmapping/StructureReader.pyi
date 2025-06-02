import java.lang


class StructureReader(object):
    """
    Interface used by structure mapped classes that need to manually deserialize themselves from
     the raw data, required when the structure contains variable length fields.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readStructure(self) -> None:
        """
        Called after an instance has been created and its context has been initialized.
        @throws IOException
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

