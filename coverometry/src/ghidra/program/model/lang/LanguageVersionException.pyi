from typing import List
import ghidra.program.model.lang
import ghidra.program.util
import ghidra.util.exception
import java.io
import java.lang


class LanguageVersionException(ghidra.util.exception.VersionException):




    @overload
    def __init__(self, msg: unicode, upgradable: bool):
        """
        Construct a language version exception
        @param msg condition detail
        @param upgradable true indicates that an upgrade is possible.
        """
        ...

    @overload
    def __init__(self, oldLanguage: ghidra.program.model.lang.Language, languageTranslator: ghidra.program.util.LanguageTranslator):
        """
        Construct a major upgradeable language version exception
        @param oldLanguage old language stub
        @param languageTranslator language transalator
        """
        ...



    def addSuppressed(self, __a0: java.lang.Throwable) -> None: ...

    @staticmethod
    def check(language: ghidra.program.model.lang.Language, languageVersion: int, languageMinorVersion: int) -> ghidra.program.model.lang.LanguageVersionException:
        """
        Check language against required version information.  If not a match or upgradeable
         a {@link LanguageNotFoundException} will be thrown.  If an upgradeable {@link LanguageVersionException}
         is returned, a major version change will also include the appropriate Old-Language stub and
         {@link LanguageTranslator} required to facilitate a language upgrade.
        @param language language corresponding to desired language ID
        @param languageVersion required major language version
        @param languageMinorVersion required minor language version.  A negative minor version will be ignored.
        @return null if language matches, otherwise an upgradeable {@link LanguageVersionException}.
        @throws LanguageNotFoundException if language is a mismatch and is not upgradeable.
        """
        ...

    @staticmethod
    def checkForLanguageChange(e: ghidra.program.model.lang.LanguageNotFoundException, languageID: ghidra.program.model.lang.LanguageID, languageVersion: int) -> ghidra.program.model.lang.LanguageVersionException:
        """
        Determine if a missing language resulting in a {@link LanguageNotFoundException} can be 
         upgraded to a replacement language via a language translation.
        @param e original {@link LanguageNotFoundException}
        @param languageID language ID of original language requested
        @param languageVersion original language major version
        @return upgradeable {@link LanguageVersionException}
        @throws LanguageNotFoundException original exception if a language transaltion is not available
        """
        ...

    def combine(self, ve: ghidra.util.exception.VersionException) -> ghidra.util.exception.VersionException:
        """
        Combine another VersionException with this one.
        @param ve another version exception
        @return this combined version exception
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def fillInStackTrace(self) -> java.lang.Throwable: ...

    def getCause(self) -> java.lang.Throwable: ...

    def getClass(self) -> java.lang.Class: ...

    def getDetailMessage(self) -> unicode: ...

    def getLanguageTranslator(self) -> ghidra.program.util.LanguageTranslator:
        """
        Old language upgrade translator if language translation required
        @return language upgrade translator or null
        """
        ...

    def getLocalizedMessage(self) -> unicode: ...

    def getMessage(self) -> unicode: ...

    def getOldLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Old language stub if language translation required
        @return Old language stub or null
        """
        ...

    def getStackTrace(self) -> List[java.lang.StackTraceElement]: ...

    def getSuppressed(self) -> List[java.lang.Throwable]: ...

    def getVersionIndicator(self) -> int:
        """
        Return a version indicator (OLDER_VERSION, NEWER_VERSION or UNKNOWN_VERSION).
         Only an OLDER_VERSION has the possibility of being upgradeable.
        """
        ...

    def hashCode(self) -> int: ...

    def initCause(self, __a0: java.lang.Throwable) -> java.lang.Throwable: ...

    def isUpgradable(self) -> bool:
        """
        Return true if the file can be upgraded to the current version.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def printStackTrace(self) -> None: ...

    @overload
    def printStackTrace(self, __a0: java.io.PrintStream) -> None: ...

    @overload
    def printStackTrace(self, __a0: java.io.PrintWriter) -> None: ...

    def setDetailMessage(self, message: unicode) -> None: ...

    def setStackTrace(self, __a0: List[java.lang.StackTraceElement]) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def languageTranslator(self) -> ghidra.program.util.LanguageTranslator: ...

    @property
    def oldLanguage(self) -> ghidra.program.model.lang.Language: ...