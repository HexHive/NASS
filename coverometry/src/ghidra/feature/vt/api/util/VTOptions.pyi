from typing import List
import ghidra.framework.options
import ghidra.util
import java.awt
import java.beans
import java.io
import java.lang
import java.util
import javax.swing
import org.jdom


class VTOptions(ghidra.framework.options.ToolOptions):




    def __init__(self, __a0: unicode): ...



    def addOptionsChangeListener(self, __a0: ghidra.framework.options.OptionsChangeListener) -> None: ...

    def contains(self, __a0: unicode) -> bool: ...

    def copy(self) -> ghidra.framework.options.ToolOptions: ...

    def copyOptions(self, __a0: ghidra.framework.options.Options) -> None: ...

    def createAlias(self, __a0: unicode, __a1: ghidra.framework.options.Options, __a2: unicode) -> None: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def findPropertyEditor(__a0: java.lang.Class) -> java.beans.PropertyEditor: ...

    def getBoolean(self, __a0: unicode, __a1: bool) -> bool: ...

    def getByteArray(self, __a0: unicode, __a1: List[int]) -> List[int]: ...

    def getCategoryHelpLocation(self, __a0: unicode) -> ghidra.util.HelpLocation: ...

    def getChildOptions(self) -> List[object]: ...

    def getClass(self) -> java.lang.Class: ...

    def getColor(self, __a0: unicode, __a1: java.awt.Color) -> java.awt.Color: ...

    def getCustomOption(self, __a0: unicode, __a1: ghidra.framework.options.CustomOption) -> ghidra.framework.options.CustomOption: ...

    def getDate(self, __a0: unicode, __a1: java.util.Date) -> java.util.Date: ...

    def getDefaultValue(self, __a0: unicode) -> object: ...

    def getDefaultValueAsString(self, __a0: unicode) -> unicode: ...

    def getDescription(self, __a0: unicode) -> unicode: ...

    def getDouble(self, __a0: unicode, __a1: float) -> float: ...

    def getEnum(self, __a0: unicode, __a1: java.lang.Enum) -> java.lang.Enum: ...

    def getFile(self, __a0: unicode, __a1: java.io.File) -> java.io.File: ...

    def getFloat(self, __a0: unicode, __a1: float) -> float: ...

    def getFont(self, __a0: unicode, __a1: java.awt.Font) -> java.awt.Font: ...

    def getHelpLocation(self, __a0: unicode) -> ghidra.util.HelpLocation: ...

    def getID(self, __a0: unicode) -> unicode: ...

    def getInt(self, __a0: unicode, __a1: int) -> int: ...

    def getKeyStroke(self, __a0: unicode, __a1: javax.swing.KeyStroke) -> javax.swing.KeyStroke: ...

    def getLeafOptionNames(self) -> List[object]: ...

    def getLong(self, __a0: unicode, __a1: long) -> long: ...

    def getName(self) -> unicode: ...

    def getObject(self, __a0: unicode, __a1: object) -> object: ...

    def getOption(self, __a0: unicode, __a1: ghidra.framework.options.OptionType, __a2: object) -> ghidra.framework.options.Option: ...

    def getOptionNames(self) -> List[object]: ...

    def getOptions(self, __a0: unicode) -> ghidra.framework.options.Options: ...

    @overload
    def getOptionsEditor(self) -> ghidra.framework.options.OptionsEditor: ...

    @overload
    def getOptionsEditor(self, __a0: unicode) -> ghidra.framework.options.OptionsEditor: ...

    def getOptionsHelpLocation(self) -> ghidra.util.HelpLocation: ...

    def getPropertyEditor(self, __a0: unicode) -> java.beans.PropertyEditor: ...

    def getRegisteredPropertyEditor(self, __a0: unicode) -> java.beans.PropertyEditor: ...

    def getString(self, __a0: unicode, __a1: unicode) -> unicode: ...

    def getType(self, __a0: unicode) -> ghidra.framework.options.OptionType: ...

    def getValueAsString(self, __a0: unicode) -> unicode: ...

    def getXmlRoot(self, __a0: bool) -> org.jdom.Element: ...

    @staticmethod
    def hasSameOptionsAndValues(__a0: ghidra.framework.options.Options, __a1: ghidra.framework.options.Options) -> bool: ...

    def hashCode(self) -> int: ...

    def isAlias(self, __a0: unicode) -> bool: ...

    def isDefaultValue(self, __a0: unicode) -> bool: ...

    def isRegistered(self, __a0: unicode) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def putObject(self, __a0: unicode, __a1: object) -> None: ...

    @overload
    def putObject(self, __a0: unicode, __a1: object, __a2: ghidra.framework.options.OptionType) -> None: ...

    @overload
    def registerOption(self, __a0: unicode, __a1: object, __a2: ghidra.util.HelpLocation, __a3: unicode) -> None: ...

    @overload
    def registerOption(self, __a0: unicode, __a1: ghidra.framework.options.OptionType, __a2: object, __a3: ghidra.util.HelpLocation, __a4: unicode) -> None: ...

    @overload
    def registerOption(self, __a0: unicode, __a1: ghidra.framework.options.OptionType, __a2: object, __a3: ghidra.util.HelpLocation, __a4: unicode, __a5: java.beans.PropertyEditor) -> None: ...

    def registerOptions(self, __a0: ghidra.framework.options.ToolOptions) -> None: ...

    @overload
    def registerOptionsEditor(self, __a0: ghidra.framework.options.OptionsEditor) -> None: ...

    @overload
    def registerOptionsEditor(self, __a0: unicode, __a1: ghidra.framework.options.OptionsEditor) -> None: ...

    def registerThemeColorBinding(self, __a0: unicode, __a1: unicode, __a2: ghidra.util.HelpLocation, __a3: unicode) -> None: ...

    def registerThemeFontBinding(self, __a0: unicode, __a1: unicode, __a2: ghidra.util.HelpLocation, __a3: unicode) -> None: ...

    def removeOption(self, __a0: unicode) -> None: ...

    def removeOptionsChangeListener(self, __a0: ghidra.framework.options.OptionsChangeListener) -> None: ...

    def removeUnusedOptions(self) -> None: ...

    def restoreDefaultValue(self, __a0: unicode) -> None: ...

    def restoreDefaultValues(self) -> None: ...

    def setBoolean(self, __a0: unicode, __a1: bool) -> None: ...

    def setByteArray(self, __a0: unicode, __a1: List[int]) -> None: ...

    def setCategoryHelpLocation(self, __a0: unicode, __a1: ghidra.util.HelpLocation) -> None: ...

    def setColor(self, __a0: unicode, __a1: java.awt.Color) -> None: ...

    def setCustomOption(self, __a0: unicode, __a1: ghidra.framework.options.CustomOption) -> None: ...

    def setDate(self, __a0: unicode, __a1: java.util.Date) -> None: ...

    def setDouble(self, __a0: unicode, __a1: float) -> None: ...

    def setEnum(self, __a0: unicode, __a1: java.lang.Enum) -> None: ...

    def setFile(self, __a0: unicode, __a1: java.io.File) -> None: ...

    def setFloat(self, __a0: unicode, __a1: float) -> None: ...

    def setFont(self, __a0: unicode, __a1: java.awt.Font) -> None: ...

    def setInt(self, __a0: unicode, __a1: int) -> None: ...

    def setKeyStroke(self, __a0: unicode, __a1: javax.swing.KeyStroke) -> None: ...

    def setLong(self, __a0: unicode, __a1: long) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def setOptionsHelpLocation(self, __a0: ghidra.util.HelpLocation) -> None: ...

    def setString(self, __a0: unicode, __a1: unicode) -> None: ...

    def takeListeners(self, __a0: ghidra.framework.options.ToolOptions) -> None: ...

    def toString(self) -> unicode: ...

    def validate(self) -> bool: ...

    def validateOptions(self) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

