import java.lang


class SearchConstants(object):
    """
    Miscellaneous constants
    """

    DEFAULT_SEARCH_LIMIT: int = 500
    SEARCH_HIGHLIGHT_COLOR: generic.theme.GColor = #00ffff
    SEARCH_HIGHLIGHT_COLOR_OPTION_NAME: unicode = u' Highlight Color'
    SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR: generic.theme.GColor = #00ffff
    SEARCH_HIGHLIGHT_CURRENT_COLOR_OPTION_NAME: unicode = u'Highlight Color for Current Match'
    SEARCH_HIGHLIGHT_NAME: unicode = u'Highlight Search Results'
    SEARCH_OPTION_NAME: unicode = u'Search'







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

