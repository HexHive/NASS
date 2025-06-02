import ghidra.app.util.bin.format.golang.structmapping
import java.lang


class FieldReadFunction(object):
    """
    Functional interface to read a structure field's value.
 
    """









    def equals(self, __a0: object) -> bool: ...

    def get(self, context: ghidra.app.util.bin.format.golang.structmapping.FieldContext) -> object:
        """
        Deserializes and returns a field's value.
        @param context context for this field
        @return value of the field
        @throws IOException if error reading
        """
        ...

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

