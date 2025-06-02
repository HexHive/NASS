from typing import List
import java.io
import java.lang


class GenericRunInfo(object):
    TEST_DIRECTORY_SUFFIX: unicode = u'-Test'



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getPreviousApplicationSettingsDir(dirName: unicode, filter: java.io.FileFilter) -> java.io.File:
        """
        Searches previous Application Settings directories 
         ({@link #getUserSettingsDirsByTime()}) to find a settings directory containing
         files that match the given file filter.  This is 
         useful for loading previous directories of saved settings files of a particular type.
 
         <p>Note: this method will ignore any test versions of settings directories.
        @param dirName the name of a settings subdir; must be relative to a settings directory
        @param filter the file filter for the files of interest
        @return the most recent file matching that name and containing at least one file
         of the given type, in a previous version's settings directory.
        """
        ...

    @staticmethod
    def getPreviousApplicationSettingsDirsByTime() -> List[java.io.File]:
        """
        This is the same as {@link #getUserSettingsDirsByTime()} except that it doesn't include the 
         current installation or installations with different release names
        @return the list of previous directories, sorted by time
        """
        ...

    @staticmethod
    def getPreviousApplicationSettingsFile(filename: unicode) -> java.io.File:
        """
        Searches previous Application Settings directories 
         ({@link #getUserSettingsDirsByTime()}) to find a file by the given name.   This is 
         useful for loading previous user settings, such as preferences.
 
         <p>Note: this method will ignore any test versions of settings directories.
        @param filename the name for which to seek; must be relative to a settings directory
        @return the most recent file matching that name found in a previous settings dir
        """
        ...

    @staticmethod
    def getProjectsDirPath() -> unicode:
        """
        Get the user's preferred projects directory.
        @return projects directory path.
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def setProjectsDirPath(path: unicode) -> None:
        """
        Set the user's current projects directory path.  Value is also retained
         within user's set of preferences.
        @param path projects directory path.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

