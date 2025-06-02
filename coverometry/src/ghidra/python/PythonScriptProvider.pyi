import generic.jar
import ghidra.app.script
import java.io
import java.lang
import java.util.regex


class PythonScriptProvider(ghidra.app.script.GhidraScriptProvider):




    def __init__(self): ...



    @overload
    def compareTo(self, that: ghidra.app.script.GhidraScriptProvider) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def createNewScript(self, newScript: generic.jar.ResourceFile, category: unicode) -> None: ...

    def deleteScript(self, scriptSource: generic.jar.ResourceFile) -> bool:
        """
        Deletes the script file and unloads the script from the script manager.
        @param scriptSource the script source file
        @return true if the script was completely deleted and cleaned up
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def getBlockCommentEnd(self) -> java.util.regex.Pattern:
        """
        {@inheritDoc}
 
         <p>
         In Python this is a triple single quote sequence, "'''".
        @return the Pattern for Python block comment openings
        """
        ...

    def getBlockCommentStart(self) -> java.util.regex.Pattern:
        """
        {@inheritDoc}
 
         <p>
         In Python this is a triple single quote sequence, "'''".
        @return the Pattern for Python block comment openings
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCommentCharacter(self) -> unicode: ...

    def getDescription(self) -> unicode: ...

    def getExtension(self) -> unicode: ...

    def getScriptInstance(self, sourceFile: generic.jar.ResourceFile, writer: java.io.PrintWriter) -> ghidra.app.script.GhidraScript: ...

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
    def blockCommentEnd(self) -> java.util.regex.Pattern: ...

    @property
    def blockCommentStart(self) -> java.util.regex.Pattern: ...

    @property
    def commentCharacter(self) -> unicode: ...

    @property
    def description(self) -> unicode: ...

    @property
    def extension(self) -> unicode: ...