from typing import List
import java.io
import java.lang
import javax.swing
import utility.function


class GhidraFileChooserModel(object):
    """
    Interface for the GhidraFileChooser data model.
     This allows the GhidraFileChooser to operate
     on files from different sources, other than
     just the local file system.
    """









    def createDirectory(self, directory: java.io.File, name: unicode) -> bool:
        """
        Creates a directory in the specified directory with the specified
         name.
        @param directory the directory in which to create the new directory
        @param name the name of the directory
        @return true if the new directory was create.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self, file: java.io.File) -> unicode:
        """
        Returns a description for the specified file.
        @param file the file
        @return a description for the specified file
        """
        ...

    def getDesktopDirectory(self) -> java.io.File:
        """
        Returns the user's desktop directory, as defined by their operating system and/or their windowing environment, or
         null if there is no desktop directory.<p>
         Example: "/home/the_user/Desktop" or "c:/Users/the_user/Desktop"
        @return desktop directory
        """
        ...

    def getHomeDirectory(self) -> java.io.File:
        """
        Returns the home directory.
        @return the home directory
        """
        ...

    def getIcon(self, file: java.io.File) -> javax.swing.Icon:
        """
        Returns an icon for the specified file.
        @param file the file
        @return an icon for the specified file
        """
        ...

    def getListing(self, directory: java.io.File, filter: java.io.FileFilter) -> List[java.io.File]:
        """
        Returns an array of the files that 
         exist in the specified directory.
        @param directory the directory
        @param filter the file filter; may be null
        @return list of files
        """
        ...

    def getRoots(self, forceUpdate: bool) -> List[java.io.File]:
        """
        Returns a list of the root drives/directories.
         <p>
         On windows, "C:\", "D:\", etc.
         <p>
         On linux, "/".
        @param forceUpdate if true, request a fresh listing, if false allow a cached result
        @return the root drives
        """
        ...

    def getSeparator(self) -> int:
        """
        Returns the file separator char.
         On windows, '\'
         On linux, '/'.
        @return the file separator char
        """
        ...

    def hashCode(self) -> int: ...

    def isAbsolute(self, file: java.io.File) -> bool:
        """
        Tests whether this abstract pathname is absolute.  The definition of
         absolute pathname is system dependent.  On UNIX systems, a pathname is
         absolute if its prefix is <code>"/"</code>.  On Microsoft Windows systems, a
         pathname is absolute if its prefix is a drive specifier followed by
         <code>"\\"</code>, or if its prefix is <code>"\\"</code>.
        @param file the file
        @return <code>true</code> if this abstract pathname is absolute,
                  <code>false</code> otherwise
        """
        ...

    def isDirectory(self, file: java.io.File) -> bool:
        """
        Tests whether the file denoted by this abstract pathname is a directory.
        @param file the file
        @return <code>true</code> if and only if the file denoted by this
                  abstract pathname exists <em>and</em> is a directory;
                  <code>false</code> otherwise
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def renameFile(self, src: java.io.File, dest: java.io.File) -> bool:
        """
        Renames the src file to the destination file.
        @param src the file to be renamed
        @param dest the new file
        @return true if the file was renamed
        """
        ...

    def setModelUpdateCallback(self, callback: utility.function.Callback) -> None:
        """
        Set the model update callback.
        @param callback the new model update callback handler
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def desktopDirectory(self) -> java.io.File: ...

    @property
    def homeDirectory(self) -> java.io.File: ...

    @property
    def modelUpdateCallback(self) -> None: ...  # No getter available.

    @modelUpdateCallback.setter
    def modelUpdateCallback(self, value: utility.function.Callback) -> None: ...

    @property
    def separator(self) -> int: ...