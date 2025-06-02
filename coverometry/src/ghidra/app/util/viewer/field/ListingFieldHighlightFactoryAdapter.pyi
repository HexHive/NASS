from typing import List
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import java.lang


class ListingFieldHighlightFactoryAdapter(object, docking.widgets.fieldpanel.support.FieldHighlightFactory):
    """
    Wrapper class to translate calls to FieldHighlightFactory into a call needed by the 
     ListingHighlightProvider.   This class holds field factory information in the text 
     field to be provided to the highlightProvider to get highlights just before the field is painted.
 
     This class is needed to allow the basic Field API to be used with more richness at the
     ListingPanel level.
    """

    NO_HIGHLIGHTS: List[docking.widgets.fieldpanel.support.Highlight] = array(docking.widgets.fieldpanel.support.Highlight)



    def __init__(self, provider: ghidra.app.util.ListingHighlightProvider):
        """
        Constructor
        @param provider the HighlightProvider that will actually compute the highlights.
        """
        ...



    def createHighlights(self, field: docking.widgets.fieldpanel.field.Field, text: unicode, cursorTextOffset: int) -> List[docking.widgets.fieldpanel.support.Highlight]: ...

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

