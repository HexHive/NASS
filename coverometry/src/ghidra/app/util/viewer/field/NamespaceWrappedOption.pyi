import ghidra.framework.options
import java.lang


class NamespaceWrappedOption(object, ghidra.framework.options.CustomOption):
    """
    An option class that allows the user to edit a related group of options pertaining to
     namespace display.
    """

    CUSTOM_OPTION_CLASS_NAME_KEY: unicode = u'CUSTOM_OPTION_CLASS'



    def __init__(self): ...



    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLocalPrefixText(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isShowLibraryInNamespace(self) -> bool: ...

    def isShowLocalNamespace(self) -> bool: ...

    def isShowNonLocalNamespace(self) -> bool: ...

    def isUseLocalPrefixOverride(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readState(self, properties: ghidra.framework.options.GProperties) -> None: ...

    def setLocalPrefixText(self, localPrefixText: unicode) -> None: ...

    def setShowLibraryInNamespace(self, showLibraryInNamespace: bool) -> None: ...

    def setShowLocalNamespace(self, showLocalNamespace: bool) -> None: ...

    def setShowNonLocalNamespace(self, showNonLocalNamespace: bool) -> None: ...

    def setUseLocalPrefixOverride(self, useLocalPrefixOverride: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeState(self, properties: ghidra.framework.options.GProperties) -> None: ...

    @property
    def localPrefixText(self) -> unicode: ...

    @localPrefixText.setter
    def localPrefixText(self, value: unicode) -> None: ...

    @property
    def showLibraryInNamespace(self) -> bool: ...

    @showLibraryInNamespace.setter
    def showLibraryInNamespace(self, value: bool) -> None: ...

    @property
    def showLocalNamespace(self) -> bool: ...

    @showLocalNamespace.setter
    def showLocalNamespace(self, value: bool) -> None: ...

    @property
    def showNonLocalNamespace(self) -> bool: ...

    @showNonLocalNamespace.setter
    def showNonLocalNamespace(self, value: bool) -> None: ...

    @property
    def useLocalPrefixOverride(self) -> bool: ...

    @useLocalPrefixOverride.setter
    def useLocalPrefixOverride(self, value: bool) -> None: ...