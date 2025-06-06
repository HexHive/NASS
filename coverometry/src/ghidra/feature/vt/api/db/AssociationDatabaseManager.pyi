from typing import List
import db
import ghidra.feature.vt.api.db
import ghidra.feature.vt.api.impl
import ghidra.feature.vt.api.main
import ghidra.program.model.address
import ghidra.util.task
import java.lang
import java.util


class AssociationDatabaseManager(object, ghidra.feature.vt.api.main.VTAssociationManager):








    def addMarkupItem(self, __a0: ghidra.feature.vt.api.impl.MarkupItemStorage) -> ghidra.feature.vt.api.impl.MarkupItemStorage: ...

    @staticmethod
    def createAssociationManager(__a0: db.DBHandle, __a1: ghidra.feature.vt.api.db.VTSessionDB) -> ghidra.feature.vt.api.db.AssociationDatabaseManager: ...

    def equals(self, __a0: object) -> bool: ...

    def getAppliedMarkupItems(self, __a0: ghidra.util.task.TaskMonitor, __a1: ghidra.feature.vt.api.main.VTAssociation) -> java.util.Collection: ...

    def getAssociation(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address) -> ghidra.feature.vt.api.main.VTAssociation: ...

    def getAssociationCount(self) -> int: ...

    @staticmethod
    def getAssociationManager(__a0: db.DBHandle, __a1: ghidra.feature.vt.api.db.VTSessionDB, __a2: db.OpenMode, __a3: ghidra.util.task.TaskMonitor) -> ghidra.feature.vt.api.db.AssociationDatabaseManager: ...

    def getAssociations(self) -> List[object]: ...

    def getClass(self) -> java.lang.Class: ...

    def getRelatedAssociationsByDestinationAddress(self, __a0: ghidra.program.model.address.Address) -> java.util.Collection: ...

    def getRelatedAssociationsBySourceAddress(self, __a0: ghidra.program.model.address.Address) -> java.util.Collection: ...

    def getRelatedAssociationsBySourceAndDestinationAddress(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address) -> java.util.Collection: ...

    def getSession(self) -> ghidra.feature.vt.api.db.VTSessionDB: ...

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

    @property
    def associationCount(self) -> int: ...

    @property
    def associations(self) -> List[object]: ...

    @property
    def session(self) -> ghidra.feature.vt.api.db.VTSessionDB: ...