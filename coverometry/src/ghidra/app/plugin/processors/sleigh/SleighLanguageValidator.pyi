import generic.jar
import java.lang


class SleighLanguageValidator(object):
    """
    Validate SLEIGH related XML configuration files: .cspec .pspec and .ldefs
 
     A ResourceFile containing an XML document can be verified with one of the
     static methods:
        - validateCspecFile
        - validateLdefsFile
        - validatePspecFile
 
     Alternately the class can be instantiated, which will allocate a single verifier
     that can be run on multiple files.
    """

    CSPECTAG_TYPE: int = 4
    CSPEC_TYPE: int = 1
    LDEFS_TYPE: int = 3
    PSPEC_TYPE: int = 2



    def __init__(self, type: int): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def validateCspecFile(cspecFile: generic.jar.ResourceFile) -> None: ...

    @staticmethod
    def validateLdefsFile(ldefsFile: generic.jar.ResourceFile) -> None: ...

    @staticmethod
    def validatePspecFile(pspecFile: generic.jar.ResourceFile) -> None: ...

    @overload
    def verify(self, specFile: generic.jar.ResourceFile) -> None:
        """
        Verify the given file against this validator.
        @param specFile is the file
        @throws SleighException with an explanation if the file does not validate
        """
        ...

    @overload
    def verify(self, title: unicode, document: unicode) -> None:
        """
        Verify an XML document as a string against this validator.
         Currently this only supports verifierType == CSPECTAG_TYPE.
        @param title is a description of the document
        @param document is the XML document body
        @throws SleighException with an explanation if the document does not validate
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

