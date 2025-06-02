from typing import List
import ghidra.app.plugin.core.navigation
import ghidra.framework.options
import java.lang
import java.util


class ProgramStartingLocationOptions(object, ghidra.framework.options.OptionsChangeListener):
    AFTER_ANALYSIS_SUB_OPTION: unicode = u'After Initial Analysis'
    ASK_TO_MOVE_DESCRIPTION: unicode = u'When initial analysis completed, asks the user if they want to reposition the program to a newly discovered starting symbol.'
    ASK_TO_MOVE_OPTION: unicode = u'After Initial Analysis.Ask To Reposition Program'
    AUTO_MOVE_DESCRIPTION: unicode = u"When initial analysis is completed, automatically repositions the program to a newly discovered starting symbol, provided the user hasn't manually moved."
    AUTO_MOVE_OPTION: unicode = u'After Initial Analysis.Auto Reposition If Not Moved'
    START_LOCATION_SUB_OPTION: unicode = u'Starting Program Location'
    START_LOCATION_TYPE_OPTION: unicode = u'Starting Program Location.Start At: '
    START_SYMBOLS_OPTION: unicode = u'Starting Program Location.Start Symbols: '
    UNDERSCORE_OPTION: unicode = u'Starting Program Location.Use Underscores:'




    class StartLocationType(java.lang.Enum):
        LAST_LOCATION: ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType = Location When Last Closed
        LOWEST_ADDRESS: ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType = Lowest Address
        LOWEST_CODE_BLOCK: ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType = Lowest Code Block Address
        SYMBOL_NAME: ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType = Preferred Symbol Name







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self, __a0: ghidra.framework.plugintool.PluginTool): ...



    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getStartLocationType(self) -> ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType: ...

    def getStartingSymbolNames(self) -> List[object]: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def optionsChanged(self, __a0: ghidra.framework.options.ToolOptions, __a1: unicode, __a2: object, __a3: object) -> None: ...

    def shouldAskToRepostionAfterAnalysis(self) -> bool: ...

    def shouldAutoRepositionIfNotMoved(self) -> bool: ...

    def toString(self) -> unicode: ...

    def useUnderscorePrefixes(self) -> bool: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def startLocationType(self) -> ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions.StartLocationType: ...

    @property
    def startingSymbolNames(self) -> List[object]: ...