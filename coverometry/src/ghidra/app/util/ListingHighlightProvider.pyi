from typing import List
import docking.widgets.fieldpanel.support
import ghidra.app.util.viewer.field
import java.lang


class ListingHighlightProvider(object):
    """
    Provider of Highlight objects appropriate ListingFields.
    """

    NO_HIGHLIGHTS: List[docking.widgets.fieldpanel.support.Highlight] = array(docking.widgets.fieldpanel.support.Highlight)







    def createHighlights(self, text: unicode, field: ghidra.app.util.viewer.field.ListingField, cursorTextOffset: int) -> List[docking.widgets.fieldpanel.support.Highlight]:
        """
        Get the highlights appropriate for the given text
        @param text the entire text contained in the field, regardless of layout.
        @param field the field being rendered.  From this field you can get the field factory and 
                the proxy object, which is usually a {@link CodeUnit}.
        @param cursorTextOffset the cursor position within the given text or -1 if no cursor in this 
                field.
        @return an array of highlight objects that indicate the location within the text string to
                 be highlighted.
        """
        ...

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

