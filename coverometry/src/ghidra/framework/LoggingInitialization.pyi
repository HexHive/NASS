import java.io
import java.lang


class LoggingInitialization(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getApplicationLogFile() -> java.io.File:
        """
        Returns the default file used for logging messages.
        @return the file
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getScriptLogFile() -> java.io.File:
        """
        Returns the default file used for logging messages.
        @return the file
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def initializeLoggingSystem() -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def reinitialize() -> None:
        """
        Signals to reload the log settings from the log configuration files in use.  This is useful
         for tests that wish to temporarily change log settings, restoring them when done.
         <p>
         This method will do nothing if {@link #initializeLoggingSystem()} has not been called.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

