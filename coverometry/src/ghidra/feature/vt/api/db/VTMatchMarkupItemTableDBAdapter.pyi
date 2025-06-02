from typing import List
import db
import ghidra.feature.vt.api.db
import ghidra.feature.vt.api.impl
import ghidra.util.task
import java.lang


class VTMatchMarkupItemTableDBAdapter(object):





    class MarkupTableDescriptor(ghidra.feature.vt.api.db.TableDescriptor):
        ADDRESS_SOURCE_COL: ghidra.feature.vt.api.db.TableColumn
        ASSOCIATION_KEY_COL: ghidra.feature.vt.api.db.TableColumn
        DESTINATION_ADDRESS_COL: ghidra.feature.vt.api.db.TableColumn
        INSTANCE: ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor
        MARKUP_TYPE_COL: ghidra.feature.vt.api.db.TableColumn
        ORIGINAL_DESTINATION_VALUE_COL: ghidra.feature.vt.api.db.TableColumn
        SOURCE_ADDRESS_COL: ghidra.feature.vt.api.db.TableColumn
        SOURCE_VALUE_COL: ghidra.feature.vt.api.db.TableColumn
        STATUS_COL: ghidra.feature.vt.api.db.TableColumn
        STATUS_DESCRIPTION_COL: ghidra.feature.vt.api.db.TableColumn



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
    def createAdapter(__a0: db.DBHandle) -> ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter: ...

    def createMarkupItemRecord(self, __a0: ghidra.feature.vt.api.impl.MarkupItemStorage) -> db.DBRecord: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getAdapter(__a0: db.DBHandle, __a1: db.OpenMode, __a2: ghidra.util.task.TaskMonitor) -> ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter: ...

    def getClass(self) -> java.lang.Class: ...

    def getRecord(self, __a0: long) -> db.DBRecord: ...

    def getRecordCount(self) -> int: ...

    @overload
    def getRecords(self) -> db.RecordIterator: ...

    @overload
    def getRecords(self, __a0: long) -> db.RecordIterator: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeMatchMarkupItemRecord(self, __a0: long) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def recordCount(self) -> int: ...

    @property
    def records(self) -> db.RecordIterator: ...