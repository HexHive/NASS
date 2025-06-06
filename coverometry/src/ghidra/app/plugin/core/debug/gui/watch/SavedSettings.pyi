from typing import List
import ghidra.docking.settings
import ghidra.framework.options
import java.lang


class SavedSettings(object):




    def __init__(self, __a0: ghidra.docking.settings.Settings): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getState(self) -> ghidra.framework.options.SaveState: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def read(self, __a0: List[ghidra.docking.settings.SettingsDefinition], __a1: ghidra.docking.settings.Settings) -> None: ...

    def setState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def write(self, __a0: List[ghidra.docking.settings.SettingsDefinition], __a1: ghidra.docking.settings.Settings) -> None: ...

    @property
    def state(self) -> ghidra.framework.options.SaveState: ...

    @state.setter
    def state(self, value: ghidra.framework.options.SaveState) -> None: ...