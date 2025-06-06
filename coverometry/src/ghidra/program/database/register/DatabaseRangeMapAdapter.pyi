from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.util
import ghidra.util.task
import java.lang


class DatabaseRangeMapAdapter(object, ghidra.program.util.RangeMapAdapter):




    def __init__(self, register: ghidra.program.model.lang.Register, dbHandle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, lock: ghidra.util.Lock, errorHandler: db.util.ErrorHandler): ...



    def checkWritableState(self) -> None: ...

    def clearAll(self) -> None:
        """
        @see ghidra.program.util.RangeMapAdapter#clearAll()
        """
        ...

    def clearRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        @see ghidra.program.util.RangeMapAdapter#clearRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def getAddressRangeIterator(self) -> ghidra.program.model.address.AddressRangeIterator:
        """
        @see ghidra.program.util.RangeMapAdapter#getAddressRangeIterator()
        """
        ...

    @overload
    def getAddressRangeIterator(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        @see ghidra.program.util.RangeMapAdapter#getAddressRangeIterator(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getValue(self, address: ghidra.program.model.address.Address) -> List[int]:
        """
        @see ghidra.program.util.RangeMapAdapter#getValue(ghidra.program.model.address.Address)
        """
        ...

    def getValueRangeContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        @see ghidra.program.util.RangeMapAdapter#getValueRangeContaining(ghidra.program.model.address.Address)
        """
        ...

    def hashCode(self) -> int: ...

    def invalidate(self) -> None: ...

    def isEmpty(self) -> bool: ...

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: long, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        @see ghidra.program.util.RangeMapAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.util.task.TaskMonitor)
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def set(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, bytes: List[int]) -> None:
        """
        @see ghidra.program.util.RangeMapAdapter#set(ghidra.program.model.address.Address, ghidra.program.model.address.Address, byte[])
        """
        ...

    def setLanguage(self, translator: ghidra.program.util.LanguageTranslator, mapReg: ghidra.program.model.lang.Register, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        @see ghidra.program.util.RangeMapAdapter#setLanguage(ghidra.program.util.LanguageTranslator, ghidra.program.model.lang.Register, ghidra.util.task.TaskMonitor)
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressRangeIterator(self) -> ghidra.program.model.address.AddressRangeIterator: ...

    @property
    def empty(self) -> bool: ...