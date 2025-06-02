from typing import List
import db
import ghidra.feature.vt.api.db
import ghidra.util.task
import java.lang


class VTAddressCorrelatorAdapter(object):





    class AddressCorrelationTableDescriptor(ghidra.feature.vt.api.db.TableDescriptor):
        DESTINATION_ADDRESS_COL: ghidra.feature.vt.api.db.TableColumn
        INSTANCE: ghidra.feature.vt.api.db.VTAddressCorrelatorAdapter.AddressCorrelationTableDescriptor
        SOURCE_ADDRESS_COL: ghidra.feature.vt.api.db.TableColumn
        SOURCE_ENTRY_COL: ghidra.feature.vt.api.db.TableColumn



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







    @staticmethod
    def createAdapter(__a0: db.DBHandle) -> ghidra.feature.vt.api.db.VTAddressCorrelatorAdapter: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getAdapter(__a0: db.DBHandle, __a1: ghidra.util.task.TaskMonitor) -> ghidra.feature.vt.api.db.VTAddressCorrelatorAdapter: ...

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

