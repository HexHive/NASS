from typing import List
import ghidra.app.decompiler
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileProcess
import ghidra.program.model.listing
import ghidra.program.model.pcode
import java.lang
import java.util


class DecompileProcess(object):
    """
    Class for communicating with a single decompiler process.
     The process controls decompilation for a single Program.
     The process is initiated by the registerProgram method.
     If the process is ready, the statusGood flag will be set
     to true.  This flag must be checked via the isReady method
     prior to invoking any of the public methods.  If the
     process isn't ready, the only way to recover is by
     reissuing the registerProgram call and making any other
     necessary initialization calls.
    """






    class DisposeState(java.lang.Enum):
        DISPOSED_ON_CANCEL: ghidra.app.decompiler.DecompileProcess.DisposeState = DISPOSED_ON_CANCEL
        DISPOSED_ON_STARTUP_FAILURE: ghidra.app.decompiler.DecompileProcess.DisposeState = DISPOSED_ON_STARTUP_FAILURE
        DISPOSED_ON_TIMEOUT: ghidra.app.decompiler.DecompileProcess.DisposeState = DISPOSED_ON_TIMEOUT
        NOT_DISPOSED: ghidra.app.decompiler.DecompileProcess.DisposeState = NOT_DISPOSED







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.decompiler.DecompileProcess.DisposeState: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.decompiler.DecompileProcess.DisposeState]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self, path: unicode): ...



    def deregisterProgram(self) -> int:
        """
        Free decompiler resources
        @return 1 if a program was actively deregistered, 0 otherwise
        @throws IOException for problems with the pipe to the decompiler
        @throws DecompileException for problems executing the command
        """
        ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisposeState(self) -> ghidra.app.decompiler.DecompileProcess.DisposeState: ...

    def hashCode(self) -> int: ...

    def isReady(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def registerProgram(self, cback: ghidra.app.decompiler.DecompileCallback, pspecxml: unicode, cspecxml: unicode, tspecxml: unicode, coretypesxml: unicode, program: ghidra.program.model.listing.Program) -> None:
        """
        Initialize decompiler for a particular platform
        @param cback = callback object for decompiler
        @param pspecxml = string containing .pspec xml
        @param cspecxml = string containing .cspec xml
        @param tspecxml = XML string containing translator spec
        @param coretypesxml = XML description of core data-types
        @param program is the program being registered
        @throws IOException for problems with the pipe to the decompiler process
        @throws DecompileException for problems executing the command
        """
        ...

    def sendCommand(self, command: unicode, response: ghidra.program.model.pcode.ByteIngest) -> None:
        """
        Send a single command to the decompiler with no parameters and return response
        @param command is the name of the command to execute
        @param response the response accumulator
        @throws IOException for any problems with the pipe to the decompiler process
        @throws DecompileException for any problems executing the command
        """
        ...

    @overload
    def sendCommand1Param(self, command: unicode, param1: unicode, response: ghidra.program.model.pcode.ByteIngest) -> None:
        """
        Send a command to the decompiler with one parameter and return the result
        @param command is the command string
        @param param1 is the parameter encoded as a string
        @param response is the result accumulator
        @throws IOException for problems with the pipe to the decompiler process
        @throws DecompileException for problems executing the command
        """
        ...

    @overload
    def sendCommand1Param(self, command: unicode, param1: ghidra.program.model.pcode.Encoder, response: ghidra.program.model.pcode.ByteIngest) -> None:
        """
        Send a command to the decompiler with one parameter and return the result
        @param command is the command string
        @param param1 is the encoded parameter
        @param response is the result accumulator
        @throws IOException for problems with the pipe to the decompiler process
        @throws DecompileException for problems executing the command
        """
        ...

    def sendCommand2Params(self, command: unicode, param1: unicode, param2: unicode, response: ghidra.program.model.pcode.ByteIngest) -> None:
        """
        Send a command with 2 parameters to the decompiler and read the result
        @param command string to send
        @param param1 is the first parameter string
        @param param2 is the second parameter string
        @param response the response accumulator
        @throws IOException for any problems with the pipe to the decompiler process
        @throws DecompileException for problems executing the command
        """
        ...

    def sendCommandTimeout(self, command: unicode, timeoutSecs: int, encodeSet: ghidra.app.decompiler.DecompInterface.EncodeDecodeSet) -> None:
        """
        Execute a command with a timeout.  Parameters are in the encodingSet.mainQuery.
         The response gets written to encodingSet.mainResponse.
        @param command the decompiler should execute
        @param timeoutSecs the number of seconds to run before timing out
        @param encodeSet contains encoded parameters and the response container
        @throws IOException for any problems with the pipe to the decompiler process
        @throws DecompileException for any problems while executing the command
        """
        ...

    def setMaxResultSize(self, maxResultSizeMBytes: int) -> None:
        """
        Set an upper limit on the amount of data that can be sent back by the decompiler in response
         to a single command.
        @param maxResultSizeMBytes is the maximum size in megabytes
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
    def disposeState(self) -> ghidra.app.decompiler.DecompileProcess.DisposeState: ...

    @property
    def maxResultSize(self) -> None: ...  # No getter available.

    @maxResultSize.setter
    def maxResultSize(self, value: int) -> None: ...

    @property
    def ready(self) -> bool: ...