from typing import List
import ghidra.docking.settings
import java.lang
import java.util.function


class FormatSettingsDefinition(object, ghidra.docking.settings.EnumSettingsDefinition):
    """
    The settings definition for the numeric display format
    """

    BINARY: int = 2
    CHAR: int = 4
    DECIMAL: int = 1
    DEF: ghidra.docking.settings.FormatSettingsDefinition = ghidra.docking.settings.FormatSettingsDefinition@cc61c08
    DEF_BINARY: ghidra.docking.settings.FormatSettingsDefinition = ghidra.docking.settings.FormatSettingsDefinition@3d288ccc
    DEF_CHAR: ghidra.docking.settings.FormatSettingsDefinition = ghidra.docking.settings.FormatSettingsDefinition@103297a9
    DEF_DECIMAL: ghidra.docking.settings.FormatSettingsDefinition = ghidra.docking.settings.FormatSettingsDefinition@6905378f
    DEF_HEX: ghidra.docking.settings.FormatSettingsDefinition = ghidra.docking.settings.FormatSettingsDefinition@cc61c08
    DEF_OCTAL: ghidra.docking.settings.FormatSettingsDefinition = ghidra.docking.settings.FormatSettingsDefinition@6d21d4ea
    HEX: int = 0
    OCTAL: int = 3







    def clear(self, settings: ghidra.docking.settings.Settings) -> None: ...

    @staticmethod
    def concat(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: List[ghidra.docking.settings.SettingsDefinition]) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def copySetting(self, settings: ghidra.docking.settings.Settings, destSettings: ghidra.docking.settings.Settings) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def filterSettingsDefinitions(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: java.util.function.Predicate) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getChoice(self, settings: ghidra.docking.settings.Settings) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    @overload
    def getDisplayChoice(self, settings: ghidra.docking.settings.Settings) -> unicode: ...

    @overload
    def getDisplayChoice(self, value: int, s1: ghidra.docking.settings.Settings) -> unicode: ...

    def getDisplayChoices(self, settings: ghidra.docking.settings.Settings) -> List[unicode]: ...

    def getFormat(self, settings: ghidra.docking.settings.Settings) -> int:
        """
        Returns the format based on the specified settings
        @param settings the instance settings or null for default value.
        @return the format value (HEX, DECIMAL, BINARY, OCTAL, CHAR), or HEX if invalid
         data in the FORMAT settings value
        """
        ...

    def getName(self) -> unicode: ...

    def getRadix(self, settings: ghidra.docking.settings.Settings) -> int:
        """
        Returns the numeric radix associated with the format identified by the specified settings.
        @param settings the instance settings.
        @return the format radix
        """
        ...

    def getRepresentationPostfix(self, settings: ghidra.docking.settings.Settings) -> unicode:
        """
        Returns a descriptive string suffix that should be appended after converting a value
         using the radix returned by {@link #getRadix(Settings)}.
        @param settings the instance settings
        @return string suffix, such as "h" for HEX, "o" for octal
        """
        ...

    def getStorageKey(self) -> unicode: ...

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