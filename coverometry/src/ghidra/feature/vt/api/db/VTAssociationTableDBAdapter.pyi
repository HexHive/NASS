from typing import List
import db
import ghidra.feature.vt.api.db
import java.lang


class VTAssociationTableDBAdapter(object):





    class AssociationTableDescriptor(ghidra.feature.vt.api.db.TableDescriptor):
        APPLIED_STATUS_COL: ghidra.feature.vt.api.db.TableColumn
        DESTINATION_ADDRESS_COL: ghidra.feature.vt.api.db.TableColumn
        INSTANCE: ghidra.feature.vt.api.db.VTAssociationTableDBAdapter.AssociationTableDescriptor
        SOURCE_ADDRESS_COL: ghidra.feature.vt.api.db.TableColumn
        STATUS_COL: ghidra.feature.vt.api.db.TableColumn
        TYPE_COL: ghidra.feature.vt.api.db.TableColumn
        VOTE_COUNT_COL: ghidra.feature.vt.api.db.TableColumn



        def __init__(self): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getColumnFields(self) -> List[db.Field]: ...

        def getColumnNames(self) -> List[unicode]: ...

        def getIndexedColumns(self) -> List[int]: ...

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



    def __init__(self): ...



    @staticmethod
    def createAdapter(__a0: db.DBHandle) -> ghidra.feature.vt.api.db.VTAssociationTableDBAdapter: ...

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

