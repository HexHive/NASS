from typing import List
import ghidra.docking.settings
import ghidra.program.model.data
import java.lang
import java.util.function


class PointerTypeSettingsDefinition(object, ghidra.docking.settings.EnumSettingsDefinition, ghidra.program.model.data.TypeDefSettingsDefinition):
    """
    The settings definition for the numeric display format
    """

    DEF: ghidra.program.model.data.PointerTypeSettingsDefinition = ghidra.program.model.data.PointerTypeSettingsDefinition@5658982b







    def clear(self, settings: ghidra.docking.settings.Settings) -> None: ...

    @staticmethod
    def concat(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: List[ghidra.docking.settings.SettingsDefinition]) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def copySetting(self, settings: ghidra.docking.settings.Settings, destSettings: ghidra.docking.settings.Settings) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def filterSettingsDefinitions(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: java.util.function.Predicate) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getAttributeSpecification(self, settings: ghidra.docking.settings.Settings) -> unicode: ...

    def getChoice(self, settings: ghidra.docking.settings.Settings) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    @overload
    def getDisplayChoice(self, settings: ghidra.docking.settings.Settings) -> unicode: ...

    @overload
    def getDisplayChoice(self, value: int, s1: ghidra.docking.settings.Settings) -> unicode: ...

    def getDisplayChoices(self, settings: ghidra.docking.settings.Settings) -> List[unicode]: ...

    def getName(self) -> unicode: ...

    def getStorageKey(self) -> unicode: ...

    def getType(self, settings: ghidra.docking.settings.Settings) -> ghidra.program.model.data.PointerType:
        """
        Returns the format based on the specified settings
        @param settings the instance settings or null for default value.
        @return the {@link PointerType}.  {@link PointerType#DEFAULT} will be returned
         if no setting has been made.
        """
        ...

    def getValueString(self, settings: ghidra.docking.settings.Settings) -> unicode: ...

    def hasSameValue(self, __a0: ghidra.docking.settings.Settings, __a1: ghidra.docking.settings.Settings) -> bool: ...

    def hasValue(self, setting: ghidra.docking.settings.Settings) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setChoice(self, settings: ghidra.docking.settings.Settings, value: int) -> None: ...

    def setDisplayChoice(self, settings: ghidra.docking.settings.Settings, choice: unicode) -> None:
        """
        Sets the settings object to the enum value indicating the specified choice as a string.
        @param settings the settings to store the value.
        @param choice enum string representing a choice in the enum.
        """
        ...

    def setType(self, settings: ghidra.docking.settings.Settings, type: ghidra.program.model.data.PointerType) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def description(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...

    @property
    def storageKey(self) -> unicode: ...