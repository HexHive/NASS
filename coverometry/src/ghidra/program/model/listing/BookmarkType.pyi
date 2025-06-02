import java.awt
import java.lang
import javax.swing


class BookmarkType(object):
    """
    Interface for bookmark types.
    """

    ANALYSIS: unicode = u'Analysis'
    ERROR: unicode = u'Error'
    INFO: unicode = u'Info'
    NOTE: unicode = u'Note'
    WARNING: unicode = u'Warning'







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getIcon(self) -> javax.swing.Icon:
        """
        Returns Icon associated with this type or null if one has not been 
         set by a plugin.
        @return the icon.
        """
        ...

    def getMarkerColor(self) -> java.awt.Color:
        """
        Returns marker color associated with this type or null if one has not been 
         set by a plugin.
        @return the color.
        """
        ...

    def getMarkerPriority(self) -> int:
        """
        Returns marker priority associated with this type or -1 if one has not been 
         set by a plugin.
        @return the priority.
        """
        ...

    def getTypeId(self) -> int:
        """
        Returns the id associated with this bookmark type.
        @return the id associated with this bookmark type.
        """
        ...

    def getTypeString(self) -> unicode:
        """
        Returns the type as a string.
        @return the type as a string.
        """
        ...

    def hasBookmarks(self) -> bool:
        """
        Returns true if there is at least one bookmark defined for this type.
        @return true if there is at least one bookmark defined for this type.
        """
        ...

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

    @property
    def icon(self) -> javax.swing.Icon: ...

    @property
    def markerColor(self) -> java.awt.Color: ...

    @property
    def markerPriority(self) -> int: ...

    @property
    def typeId(self) -> int: ...

    @property
    def typeString(self) -> unicode: ...