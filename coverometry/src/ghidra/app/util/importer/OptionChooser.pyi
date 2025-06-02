from typing import List
import ghidra.program.model.address
import java.lang


class OptionChooser(object):
    DEFAULT_OPTIONS: ghidra.app.util.importer.OptionChooser = ghidra.app.util.importer.OptionChooser$$Lambda$348/0x0000000100e06ee0@287c75e6







    def choose(self, __a0: List[object], __a1: ghidra.program.model.address.AddressFactory) -> List[object]: ...

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

