import ghidra.framework.options
import java.lang


class FileOffsetFieldOptionsWrappedOption(object, ghidra.framework.options.CustomOption):
    """
    An option class that allows the user to edit a related group of options pertaining to
     File Offset field display
    """

    CUSTOM_OPTION_CLASS_NAME_KEY: unicode = u'CUSTOM_OPTION_CLASS'



    def __init__(self):
        """
        Default constructor, required for persistence
        """
        ...



    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readState(self, properties: ghidra.framework.options.GProperties) -> None: ...

    def setShowFilename(self, showFilename: bool) -> None:
        """
        Sets whether or not to show the filename
        @param showFilename True to show the filename, false to hide it
        """
        ...

    def setUseHex(self, useHex: bool) -> None:
        """
        Sets whether or not to display the file offset in hexadecimal
        @param useHex True to display the file offset in hexadecimal, false for decimal
        """
        ...

    def showFilename(self) -> bool:
        """
        Returns whether or not to show the filename
        @return True if the filename is to be shown; otherwise, false
        """
        ...

    def toString(self) -> unicode: ...

    def useHex(self) -> bool:
        """
        Returns whether or not to display the file offset in hexadecimal
        @return True if the file offset is to be displayed in hexadecimal; otherwise, false
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeState(self, properties: ghidra.framework.options.GProperties) -> None: ...

