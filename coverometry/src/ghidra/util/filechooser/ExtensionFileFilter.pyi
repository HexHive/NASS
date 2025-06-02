from typing import List
import ghidra.util.filechooser
import java.io
import java.lang


class ExtensionFileFilter(object, ghidra.util.filechooser.GhidraFileFilter):
    """
    A convenience implementation of FileFilter that filters out
     all files except for those type extensions that it knows about.
 
     Extensions are of the type "foo" (no leading dot). Case is ignored.
 
     Example - create a new filter that filters out all files
     but gif and jpg image files:
 
         GhidraFileChooser chooser = new GhidraFileChooser();
         chooser.addFileFilter(ExtensionFilFilter.forExtensions("JPEG and GIF Images", "gif", "jpg"));

    """

    ALL: ghidra.util.filechooser.GhidraFileFilter = ghidra.util.filechooser.GhidraFileFilter$1@591f8d8a



    @overload
    def __init__(self, extension: unicode, description: unicode):
        """
        Creates a file filter that accepts the given file type.
         Example: new ExtensionFileFilter("jpg", "JPEG Images");
        @param extension file extension to match, without leading dot
        @param description descriptive string of the filter
        """
        ...

    @overload
    def __init__(self, filters: List[unicode], description: unicode):
        """
        Creates a file filter from the given string array and description.
         Example: new ExtensionFileFilter(String {"gif", "jpg"}, "Gif and JPG Images");
        @param filters array of file name extensions, each without a leading dot
        @param description descriptive string of the filter
        """
        ...



    def accept(self, f: java.io.File, model: ghidra.util.filechooser.GhidraFileChooserModel) -> bool:
        """
        Return true if this file should be shown in the directory pane,
         false if it shouldn't.

         Files that begin with "." are ignored.
        @see FileFilter#accept
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def forExtensions(description: unicode, exts: List[unicode]) -> ghidra.util.filechooser.ExtensionFileFilter:
        """
        Creates a {@link ExtensionFileFilter} in a varargs friendly way.
        @param description String description of this set of file extensions.
        @param exts variable length list of file extensions, without leading dot.
        @return new {@link ExtensionFileFilter} instance.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

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
    def description(self) -> unicode: ...