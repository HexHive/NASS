import docking.widgets.fieldpanel.support
import ghidra.program.model.address
import java.lang


class SelectionTranslator(object):








    @overload
    def convertAddressToField(self, __a0: ghidra.program.model.address.Address) -> docking.widgets.fieldpanel.support.FieldSelection: ...

    @overload
    def convertAddressToField(self, __a0: ghidra.program.model.address.AddressRange) -> docking.widgets.fieldpanel.support.FieldSelection: ...

    @overload
    def convertAddressToField(self, __a0: ghidra.program.model.address.AddressSetView) -> docking.widgets.fieldpanel.support.FieldSelection: ...

    def convertFieldToAddress(self, __a0: docking.widgets.fieldpanel.support.FieldSelection) -> ghidra.program.model.address.AddressSetView: ...

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

