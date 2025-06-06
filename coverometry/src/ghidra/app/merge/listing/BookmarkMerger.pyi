import ghidra.app.merge.listing
import java.lang


class BookmarkMerger(ghidra.app.merge.listing.AbstractListingMerger):
    """
    Class for merging bookmark changes. This class can merge non-conflicting
     bookmark changes that were made to the checked out version. It can determine
     where there are conflicts between the latest checked in version and my
     checked out version. It can then manually merge the conflicting bookmarks.
     Important: This class is intended to be used only for a single program 
     version merge. It should be constructed, followed by an autoMerge(), and lastly
     each address with a conflict should have mergeConflicts() called on it.
    """









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

