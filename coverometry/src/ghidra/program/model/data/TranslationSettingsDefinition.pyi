from typing import List
import ghidra.docking.settings
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang
import java.util
import java.util.function


class TranslationSettingsDefinition(ghidra.docking.settings.JavaEnumSettingsDefinition):
    """
    SettingsDefinition for translation display, handles both the toggle of
      "show" vs "don't show", as well as accessing the translated value.
    """

    TRANSLATION: ghidra.program.model.data.TranslationSettingsDefinition = ghidra.program.model.data.TranslationSettingsDefinition@4a256711
    TRANSLATION_PROPERTY_MAP_NAME: unicode




    class TRANSLATION_ENUM(java.lang.Enum):
        SHOW_ORIGINAL: ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION_ENUM = show original
        SHOW_TRANSLATED: ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION_ENUM = show translated







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def invert(self) -> ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION_ENUM: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION_ENUM: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION_ENUM]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def clear(self, settings: ghidra.docking.settings.Settings) -> None: ...

    @staticmethod
    def concat(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: List[ghidra.docking.settings.SettingsDefinition]) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def copySetting(self, srcSettings: ghidra.docking.settings.Settings, destSettings: ghidra.docking.settings.Settings) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def filterSettingsDefinitions(__a0: List[ghidra.docking.settings.SettingsDefinition], __a1: java.util.function.Predicate) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getChoice(self, settings: ghidra.docking.settings.Settings) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultEnum(self) -> object:
        """
        Returns the Enum instance that is the default Enum for this {@link SettingsDefinition}.
        @return Enum
        """
        ...

    def getDescription(self) -> unicode: ...

    def getDisplayChoice(self, value: int, settings: ghidra.docking.settings.Settings) -> unicode: ...

    def getDisplayChoices(self, settings: ghidra.docking.settings.Settings) -> List[unicode]: ...

    def getEnumByOrdinal(self, ordinal: int) -> object:
        """
        Returns the Enum instance that corresponds to the specified ordinal value.
        @param ordinal integer that corresponds to an Enum.
        @return Enum
        """
        ...

    @overload
    def getEnumValue(self, settings: ghidra.docking.settings.Settings) -> object:
        """
        Returns an enum instance that corresponds to the setting stored, or the
         {@link #getDefaultEnum() default enum} if the setting has not been assigned yet.
        @param settings {@link Settings} object that stores the settings values.
        @return Enum&lt;T&gt; value, or {@link #getDefaultEnum()} if not present.
        """
        ...

    @overload
    def getEnumValue(self, __a0: ghidra.docking.settings.Settings, __a1: java.lang.Enum) -> java.lang.Enum: ...

    def getName(self) -> unicode: ...

    def getOrdinalByString(self, stringValue: unicode) -> int:
        """
        returns the Enum's ordinal using the Enum's string representation.
        @param stringValue Enum's string rep
        @return integer index of the Enum
        """
        ...

    def getStorageKey(self) -> unicode: ...

    def getTranslatedValue(self, data: ghidra.program.model.listing.Data) -> unicode:
        """
        Get the translated string value which been set at the specified address.
        @param data defined string data which may have a translation
        @return translated string value or null
        """
        ...

    def getValueString(self, settings: ghidra.docking.settings.Settings) -> unicode: ...

    def hasSameValue(self, __a0: ghidra.docking.settings.Settings, __a1: ghidra.docking.settings.Settings) -> bool: ...

    def hasTranslatedValue(self, data: ghidra.program.model.listing.Data) -> bool:
        """
        Determine if a translated string value has been set at the specified address.
        @param data defined string data which may have a translation
        @return true if translated string has been stored else false
        """
        ...

    def hasValue(self, setting: ghidra.docking.settings.Settings) -> bool: ...

    def hashCode(self) -> int: ...

    def isShowTranslated(self, settings: ghidra.docking.settings.Settings) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setChoice(self, settings: ghidra.docking.settings.Settings, value: int) -> None: ...

    def setEnumValue(self, __a0: ghidra.docking.settings.Settings, __a1: java.lang.Enum) -> None: ...

    def setShowTranslated(self, settings: ghidra.docking.settings.Settings, shouldShowTranslatedValue: bool) -> None: ...

    def setTranslatedValue(self, data: ghidra.program.model.listing.Data, translatedValue: unicode) -> None:
        """
        Set the translated string value at the specified address.
        @param data defined string data which may have a translation
        @param translatedValue translated string value or null to clear
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

