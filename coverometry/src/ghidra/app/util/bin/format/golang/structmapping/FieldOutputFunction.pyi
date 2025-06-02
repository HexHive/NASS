import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.data
import java.lang


class FieldOutputFunction(object):
    """
    A function that adds a field to a Ghidra structure using annotated field information
     found in a Java class.
    """









    def addFieldToStructure(self, context: ghidra.app.util.bin.format.golang.structmapping.StructureContext, structure: ghidra.program.model.data.Structure, fieldOutputInfo: ghidra.app.util.bin.format.golang.structmapping.FieldOutputInfo) -> None:
        """
        Adds the specified field (in {@code fieldOutputInfo}) to the structure.
        @param context {@link StructureContext}
        @param structure {@link Structure} data type
        @param fieldOutputInfo {@link FieldOutputInfo} field info
        @throws IOException if error
        """
        ...

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

