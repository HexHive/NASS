import ghidra.feature.vt.api.main
import java.lang


class AssociationHook(object):








    def associationAccepted(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> None: ...

    def associationCleared(self, __a0: ghidra.feature.vt.api.main.VTAssociation) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markupItemStatusChanged(self, __a0: ghidra.feature.vt.api.main.VTMarkupItem) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

