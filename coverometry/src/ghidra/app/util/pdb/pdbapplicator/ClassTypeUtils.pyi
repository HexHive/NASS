import ghidra.app.util.pdb.pdbapplicator
import ghidra.program.model.data
import java.lang


class ClassTypeUtils(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    @staticmethod
    def getInternalsCategoryPath(__a0: ghidra.app.util.pdb.pdbapplicator.CompositeTypeApplier) -> ghidra.program.model.data.CategoryPath: ...

    @overload
    @staticmethod
    def getInternalsCategoryPath(__a0: ghidra.program.model.data.Composite) -> ghidra.program.model.data.CategoryPath: ...

    @overload
    @staticmethod
    def getInternalsDataTypePath(__a0: ghidra.app.util.pdb.pdbapplicator.CompositeTypeApplier, __a1: unicode) -> ghidra.program.model.data.DataTypePath: ...

    @overload
    @staticmethod
    def getInternalsDataTypePath(__a0: ghidra.program.model.data.Composite, __a1: unicode) -> ghidra.program.model.data.DataTypePath: ...

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

