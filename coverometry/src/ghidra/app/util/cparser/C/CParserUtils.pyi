from typing import List
import ghidra.app.services
import ghidra.app.util.cparser.C.CParserUtils
import ghidra.app.util.cparser.CPP
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.io
import java.lang


class CParserUtils(object):





    class CParseResults(java.lang.Record):




        def __init__(self, __a0: ghidra.app.util.cparser.CPP.PreProcessor, __a1: unicode, __a2: unicode, __a3: bool): ...



        def cParseMessages(self) -> unicode: ...

        def cppParseMessages(self) -> unicode: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getFormattedParseMessage(self, __a0: unicode) -> unicode: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def preProcessor(self) -> ghidra.app.util.cparser.CPP.PreProcessor: ...

        def successful(self) -> bool: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getFile(parent: unicode, filename: unicode) -> java.io.File: ...

    @staticmethod
    def handleParseProblem(t: java.lang.Throwable, functionString: unicode) -> unicode:
        """
        Given a throwable, attempt pull out the significant error parts to generate a 
         user-friendly error message.
        @param t the throwable to examine, originating from the {@link CParser}.
        @param functionString the full function signature text that was parsed by the parser.
        @return a user-friendly error message, or null if this class did not know how to 
                 handle the given exception.
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    @staticmethod
    def parseHeaderFiles(openDTMgrs: List[ghidra.program.model.data.DataTypeManager], filenames: List[unicode], args: List[unicode], dataFileName: unicode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.data.FileDataTypeManager:
        """
        Parse a set of C Header files and associated parsing arguments, returning a new File Data TypeManager
         with in the provided dataFileName.
 
         Note: Using another open archive while parsing will cause:
         - a dependence on the other archive
         - any missing data types while parsing are supplied if present from an openDTMgr
         - after parsing all data types parsed with an equivalent data type in any openDTMgr
             replaced by the data type from the openDTMgr
     
         NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
        @param openDTMgrs array of datatypes managers to use for undefined data types
        @param filenames names of files in order to parse, could include strings with
                "#" at start, which are ignored as comments
        @param args arguments for parsing, "-D<defn>=", "-I<includepath>"
        @param dataFileName name of data type archive file (include the .gdt extension)
        @param monitor used to cancel or provide results
        @return the data types in the ghidra .gdt archive file
        @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
        @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
        @throws IOException if there io are errors saving the archive
        """
        ...

    @overload
    @staticmethod
    def parseHeaderFiles(openDTMgrs: List[ghidra.program.model.data.DataTypeManager], filenames: List[unicode], includePaths: List[unicode], args: List[unicode], dataFileName: unicode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.data.FileDataTypeManager:
        """
        Parse a set of C Header files and associated parsing arguments, returning a new File Data TypeManager
         with in the provided dataFileName.
 
         Note: Using another open archive while parsing will cause:
         - a dependence on the other archive
         - any missing data types while parsing are supplied if present from an openDTMgr
         - after parsing all data types parsed with an equivalent data type in any openDTMgr
             replaced by the data type from the openDTMgr
     
         NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
        @param openDTMgrs array of datatypes managers to use for undefined data types
        @param filenames names of files in order to parse, could include strings with
                "#" at start, which are ignored as comments
        @param includePaths paths to include files, instead of using "-I<includepath>" in args
        @param args arguments for parsing, "-D<defn>=", ( "-I<includepath>" use includePaths parm instead)
        @param dataFileName name of data type archive file (include the .gdt extension)
        @param monitor used to cancel or provide results
        @return the data types in the ghidra .gdt archive file
        @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
        @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
        @throws IOException if there io are errors saving the archive
        """
        ...

    @overload
    @staticmethod
    def parseHeaderFiles(openDTmanagers: List[ghidra.program.model.data.DataTypeManager], filenames: List[unicode], includePaths: List[unicode], args: List[unicode], dtMgr: ghidra.program.model.data.DataTypeManager, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.cparser.C.CParserUtils.CParseResults:
        """
        Parse a set of C Header files and associated parsing arguments, data types are added to the provided
         DTMgr.
 
         Note: Using another open archive while parsing will cause:
         - a dependence on the other archive
         - any missing data types while parsing are supplied if present from an openDTMgr
         - after parsing all data types parsed with an equivalent data type in any openDTMgr
             replaced by the data type from the openDTMgr
     
         NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
 
         NOTE: The DTMgr should have been created with the correct data type organization from a language/compilerspec
               if there could be variants in datatype defintions when using the generic data type manager data organization
               for example in a generic FileDataTypeManager int and long are size 4. This will change in the future,
               but with the current implementation, beware!
        @param openDTmanagers array of datatypes managers to use for undefined data types
        @param filenames names of files in order to parse, could include strings with
                "#" at start, which are ignored as comments
        @param includePaths paths to include files, instead of using "-I<includepath>" in args
        @param args arguments for parsing, "-D<defn>=", ( "-I<includepath>" use includePaths parm instead)
        @param dtMgr datatypes will be populated into this provided DTMgr, can pass Program or File DTMgr
        @param monitor used to cancel or provide results
        @return a formatted string of any output from pre processor parsing or C parsing
        @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
        @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
        """
        ...

    @overload
    @staticmethod
    def parseHeaderFiles(openDTMgrs: List[ghidra.program.model.data.DataTypeManager], filenames: List[unicode], args: List[unicode], existingDTMgr: ghidra.program.model.data.DataTypeManager, languageId: unicode, compileSpecId: unicode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.cparser.C.CParserUtils.CParseResults:
        """
        Parse a set of C Header files and associated parsing arguments, data types are added to the provided
         DTMgr.

         Note: Using another open archive while parsing will cause:
         - a dependence on the other archive
         - any missing data types while parsing are supplied if present from an openDTMgr
         - after parsing all data types parsed with an equivalent data type in any openDTMgr
             replaced by the data type from the openDTMgr
     
         NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
 
         NOTE: Providing the correct languageID and compilerSpec is very important for header files that might use sizeof()
        @param openDTMgrs array of datatypes managers to use for undefined data types
        @param filenames names of files in order to parse, could include strings with
                "#" at start, which are ignored as comments
        @param args arguments for parsing, "-D<defn>=", ( "-I<includepath>" use includePaths parm instead)
        @param existingDTMgr datatypes will be populated into this provided DTMgr, can pass Program or File DTMgr
        @param languageId language identication to use for data type organization definitions (int, long, ptr size)
        @param compileSpecId compiler specification to use for parsing
        @param monitor used to cancel or provide results
        @return a formatted string of any output from pre processor parsing or C parsing
        @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
        @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
        @throws IOException if there io are errors saving the archive
        """
        ...

    @overload
    @staticmethod
    def parseHeaderFiles(openDTMgrs: List[ghidra.program.model.data.DataTypeManager], filenames: List[unicode], includePaths: List[unicode], args: List[unicode], dataFileName: unicode, languageId: unicode, compileSpecId: unicode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.data.FileDataTypeManager:
        """
        Parse a set of C Header files and associated parsing arguments, returning a new File Data TypeManager
         with in the provided dataFileName.
 
         Note: Using another open archive while parsing will cause:
         - a dependence on the other archive
         - any missing data types while parsing are supplied if present from an openDTMgr
         - after parsing all data types parsed with an equivalent data type in any openDTMgr
             replaced by the data type from the openDTMgr
     
         NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
 
         NOTE: Providing the correct languageID and compilerSpec is very important for header files that might use sizeof()
        @param openDTMgrs array of datatypes managers to use for undefined data types
        @param filenames names of files in order to parse, could include strings with
                "#" at start, which are ignored as comments
        @param includePaths path to include files, could also be in args with "-I<includepath>"
        @param args arguments for parsing, "-D<defn>=", "-I<includepath>"
        @param dataFileName name of data type archive file (include the .gdt extension)
        @param languageId language identication to use for data type organization definitions (int, long, ptr size)
        @param compileSpecId compiler specification to use for parsing
        @param monitor used to cancel or provide results
        @return the data types in the ghidra .gdt archive file
        @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
        @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
        @throws IOException if there io are errors saving the archive
        """
        ...

    @overload
    @staticmethod
    def parseHeaderFiles(openDTMgrs: List[ghidra.program.model.data.DataTypeManager], filenames: List[unicode], includePaths: List[unicode], args: List[unicode], existingDTMgr: ghidra.program.model.data.DataTypeManager, languageId: unicode, compileSpecId: unicode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.cparser.C.CParserUtils.CParseResults:
        """
        Parse a set of C Header files and associated parsing arguments, data types are added to the provided
         DTMgr.

         Note: Using another open archive while parsing will cause:
         - a dependence on the other archive
         - any missing data types while parsing are supplied if present from an openDTMgr
         - after parsing all data types parsed with an equivalent data type in any openDTMgr
             replaced by the data type from the openDTMgr
     
         NOTE: This will only occur if the data type from the openDTMgr's is equivalent.
 
         NOTE: Providing the correct languageID and compilerSpec is very important for header files that might use sizeof()
        @param openDTMgrs array of datatypes managers to use for undefined data types
        @param filenames names of files in order to parse, could include strings with
                "#" at start, which are ignored as comments
        @param includePaths paths to include files, instead of using "-I<includepath>" in args
        @param args arguments for parsing, "-D<defn>=", ( "-I<includepath>" use includePaths parm instead)
        @param existingDTMgr datatypes will be populated into this provided DTMgr, can pass Program or File DTMgr
        @param languageId language identication to use for data type organization definitions (int, long, ptr size)
        @param compileSpecId compiler specification to use for parsing
        @param monitor used to cancel or provide results
        @return a formatted string of any output from pre processor parsing or C parsing
        @throws ghidra.app.util.cparser.C.ParseException for catastrophic errors in C parsing
        @throws ghidra.app.util.cparser.CPP.ParseException for catastrophic errors in Preprocessor macro parsing
        @throws IOException if there io are errors saving the archive
        """
        ...

    @overload
    @staticmethod
    def parseSignature(service: ghidra.app.services.DataTypeManagerService, program: ghidra.program.model.listing.Program, signatureText: unicode) -> ghidra.program.model.data.FunctionDefinitionDataType:
        """
        Parse the given function signature text.  Any exceptions will be handled herein
         by showing an error dialog (null is returned in that case).
        @param service the service used to access DataTypeManagers or null to use only the program's
         data type manager.
        @param program the program against which data types will be resolved
        @param signatureText the signature to parse
        @return the data type that is created as a result of parsing; null if there was a problem
        @see #parseSignature(DataTypeManagerService, Program, String, boolean)
        """
        ...

    @overload
    @staticmethod
    def parseSignature(serviceProvider: ghidra.framework.plugintool.ServiceProvider, program: ghidra.program.model.listing.Program, signatureText: unicode) -> ghidra.program.model.data.FunctionDefinitionDataType:
        """
        Parse the given function signature text.  Any exceptions will be handled herein
         by showing an error dialog (null is returned in that case).
        @param serviceProvider the service provider used to access DataTypeManagers
        @param program the program against which data types will be resolved
        @param signatureText the signature to parse
        @return the data type that is created as a result of parsing; null if there was a problem
        @see #parseSignature(DataTypeManagerService, Program, String)
        @see #parseSignature(DataTypeManagerService, Program, String, boolean)
        """
        ...

    @overload
    @staticmethod
    def parseSignature(service: ghidra.app.services.DataTypeManagerService, program: ghidra.program.model.listing.Program, signatureText: unicode, handleExceptions: bool) -> ghidra.program.model.data.FunctionDefinitionDataType:
        """
        Parse the given function signature text.  Any exceptions will be handled herein
         by showing an error dialog (null is returned in that case).
        @param service the service used to access DataTypeManagers or null to use only the program's
         data type manager.
        @param program the program against which data types will be resolved
        @param signatureText the signature to parse
        @param handleExceptions true signals that this method should deal with exceptions, 
                showing error messages as necessary; false signals to throw any encountered
                parsing exceptions.  This allows clients to perform exception handling that
                better matches their workflow.
        @return the data type that is created as a result of parsing; null if there was a problem
        @throws ParseException for catastrophic errors in C parsing
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

