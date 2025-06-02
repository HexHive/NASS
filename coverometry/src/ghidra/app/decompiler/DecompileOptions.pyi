from typing import List
import ghidra.app.decompiler
import ghidra.app.decompiler.DecompileOptions
import ghidra.framework.options
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.model.symbol
import java.awt
import java.lang
import java.util


class DecompileOptions(object):
    """
    Configuration options for the decompiler
     This stores the options and can create an XML
     string to be sent to the decompiler process
    """

    DEFAULT_FONT_ID: unicode = u'font.decompiler'
    SUGGESTED_DECOMPILE_TIMEOUT_SECS: int = 30
    SUGGESTED_MAX_INSTRUCTIONS: int = 100000
    SUGGESTED_MAX_JUMPTABLE_ENTRIES: int = 1024
    SUGGESTED_MAX_PAYLOAD_BYTES: int = 50




    class AliasBlockEnum(java.lang.Enum):
        All: ghidra.app.decompiler.DecompileOptions.AliasBlockEnum = All Data-types
        Array: ghidra.app.decompiler.DecompileOptions.AliasBlockEnum = Arrays and Structures
        None: ghidra.app.decompiler.DecompileOptions.AliasBlockEnum = None
        Struct: ghidra.app.decompiler.DecompileOptions.AliasBlockEnum = Structures







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def getOptionString(self) -> unicode: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.decompiler.DecompileOptions.AliasBlockEnum: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.decompiler.DecompileOptions.AliasBlockEnum]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def optionString(self) -> unicode: ...




    class NanIgnoreEnum(java.lang.Enum):
        All: ghidra.app.decompiler.DecompileOptions.NanIgnoreEnum = Ignore all
        Compare: ghidra.app.decompiler.DecompileOptions.NanIgnoreEnum = Ignore with comparisons
        None: ghidra.app.decompiler.DecompileOptions.NanIgnoreEnum = Ignore none







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def getOptionString(self) -> unicode: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.decompiler.DecompileOptions.NanIgnoreEnum: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.decompiler.DecompileOptions.NanIgnoreEnum]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def optionString(self) -> unicode: ...




    class IntegerFormatEnum(java.lang.Enum):
        BestFit: ghidra.app.decompiler.DecompileOptions.IntegerFormatEnum = Best Fit
        Decimal: ghidra.app.decompiler.DecompileOptions.IntegerFormatEnum = Force Decimal
        Hexadecimal: ghidra.app.decompiler.DecompileOptions.IntegerFormatEnum = Force Hexadecimal







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def getOptionString(self) -> unicode: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.decompiler.DecompileOptions.IntegerFormatEnum: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.decompiler.DecompileOptions.IntegerFormatEnum]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def optionString(self) -> unicode: ...




    class NamespaceStrategy(java.lang.Enum):
        All: ghidra.app.decompiler.DecompileOptions.NamespaceStrategy = Always
        Minimal: ghidra.app.decompiler.DecompileOptions.NamespaceStrategy = Minimally
        Never: ghidra.app.decompiler.DecompileOptions.NamespaceStrategy = Never







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def getOptionString(self) -> unicode: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.decompiler.DecompileOptions.NamespaceStrategy: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.decompiler.DecompileOptions.NamespaceStrategy]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def optionString(self) -> unicode: ...




    class CommentStyleEnum(java.lang.Enum):
        CPPStyle: ghidra.app.decompiler.DecompileOptions.CommentStyleEnum = // C++-style comments
        CStyle: ghidra.app.decompiler.DecompileOptions.CommentStyleEnum = /* C-style comments */







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
        def valueOf(__a0: unicode) -> ghidra.app.decompiler.DecompileOptions.CommentStyleEnum: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.decompiler.DecompileOptions.CommentStyleEnum]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self): ...



    def encode(self, encoder: ghidra.program.model.pcode.Encoder, iface: ghidra.app.decompiler.DecompInterface) -> None:
        """
        Encode all the configuration options to a stream for the decompiler process.
         This object is global to all decompile processes so we can tailor to the specific process
         by passing in the interface.
        @param encoder is the stream encoder
        @param iface specific DecompInterface being sent options
        @throws IOException for errors writing to the underlying stream
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBackgroundColor(self) -> java.awt.Color:
        """
        @return the background color for the decompiler window
        """
        ...

    def getCacheSize(self) -> int:
        """
        Return the maximum number of decompiled function results that should be cached
         by the controller of the decompiler process.
        @return the number of functions to cache
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCommentColor(self) -> java.awt.Color:
        """
        @return color used to display comments
        """
        ...

    def getCommentStyle(self) -> ghidra.app.decompiler.DecompileOptions.CommentStyleEnum:
        """
        @return the style in which comments are printed in decompiler output
        """
        ...

    def getConstantColor(self) -> java.awt.Color:
        """
        @return color associated with constant tokens
        """
        ...

    def getCurrentVariableHighlightColor(self) -> java.awt.Color:
        """
        @return the color used display the current highlighted variable
        """
        ...

    def getDefaultColor(self) -> java.awt.Color:
        """
        @return color for generic syntax or other unspecified tokens
        """
        ...

    def getDefaultFont(self) -> java.awt.Font:
        """
        @return the font that should be used to render decompiler output
        """
        ...

    def getDefaultTimeout(self) -> int:
        """
        If the time a decompiler process is allowed to analyze a single
         function exceeds this value, decompilation is aborted.
        @return the maximum time in seconds
        """
        ...

    def getDisplayLanguage(self) -> ghidra.program.model.lang.DecompilerLanguage:
        """
        @return the source programming language that decompiler output is rendered in
        """
        ...

    def getErrorColor(self) -> java.awt.Color:
        """
        @return color used on tokens that need to warn of an error or other unusual conditions
        """
        ...

    def getFunctionColor(self) -> java.awt.Color:
        """
        @return color associated with a function name token
        """
        ...

    def getGlobalColor(self) -> java.awt.Color:
        """
        @return color associated with global variable tokens
        """
        ...

    def getKeywordColor(self) -> java.awt.Color:
        """
        @return color associated with keyword tokens
        """
        ...

    def getMaxInstructions(self) -> int:
        """
        If the number of assembly instructions in a function exceeds this value, the function
         is not decompiled.
        @return the maximum number of instructions
        """
        ...

    def getMaxJumpTableEntries(self) -> int:
        """
        If the number of entries in a single jumptable exceeds this value, the decompiler will
         not recover the table and control flow from the indirect jump corresponding to the table
         will not be followed.
        @return the maximum number of entries
        """
        ...

    def getMaxPayloadMBytes(self) -> int:
        """
        If the size (in megabytes) of the payload returned by the decompiler
         process exceeds this value for a single function, decompilation is
         aborted.
        @return the maximum number of megabytes in a function payload
        """
        ...

    def getMaxWidth(self) -> int:
        """
        @return the maximum number of characters the decompiler displays in a single line of output
        """
        ...

    def getMiddleMouseHighlightButton(self) -> int:
        """
        @return the mouse button that should be used to toggle the primary token highlight
        """
        ...

    def getMiddleMouseHighlightColor(self) -> java.awt.Color:
        """
        @return color used to highlight token(s) selected with a middle button clock
        """
        ...

    def getNameTransformer(self) -> ghidra.program.model.symbol.NameTransformer:
        """
        Retrieve the transformer being applied to data-type, function, and namespace names.
         If no transform is being applied, a pass-through object is returned.
        @return the transformer object
        """
        ...

    def getParameterColor(self) -> java.awt.Color:
        """
        @return color associated with parameter tokens
        """
        ...

    def getProtoEvalModel(self) -> unicode:
        """
        @return the default prototype to assume if no other information about a function is known
        """
        ...

    def getSearchHighlightColor(self) -> java.awt.Color:
        """
        @return color used to highlight search results
        """
        ...

    def getSpecialColor(self) -> java.awt.Color:
        """
        @return color associated with volatile variables or other special tokens
        """
        ...

    def getTypeColor(self) -> java.awt.Color:
        """
        @return color associated with data-type tokens
        """
        ...

    def getVariableColor(self) -> java.awt.Color:
        """
        @return color associated with (local) variable tokens
        """
        ...

    def grabFromProgram(self, program: ghidra.program.model.listing.Program) -> None:
        """
        Grab all the decompiler options from the program specifically
         and cache them in this object.
        @param program the program whose "program options" are relevant to the decompiler
        """
        ...

    def grabFromToolAndProgram(self, fieldOptions: ghidra.framework.options.ToolOptions, opt: ghidra.framework.options.ToolOptions, program: ghidra.program.model.listing.Program) -> None:
        """
        Grab all the decompiler options from various sources within a specific tool and program
         and cache them in this object.
        @param fieldOptions the Options object containing options specific to listing fields
        @param opt the Options object that contains the "tool options" specific to the decompiler
        @param program the program whose "program options" are relevant to the decompiler
        """
        ...

    def hashCode(self) -> int: ...

    def isConventionPrint(self) -> bool:
        """
        @return true if calling convention names are displayed as part of function signatures
        """
        ...

    def isDisplayLineNumbers(self) -> bool:
        """
        @return true if line numbers should be displayed with decompiler output.
        """
        ...

    def isEOLCommentIncluded(self) -> bool:
        """
        @return true if End-of-line comments are included as part of decompiler output
        """
        ...

    def isEliminateUnreachable(self) -> bool:
        """
        @return true if the decompiler currently eliminates unreachable code
        """
        ...

    def isHeadCommentIncluded(self) -> bool:
        """
        @return true if function header comments are included as part of decompiler output
        """
        ...

    def isNoCastPrint(self) -> bool:
        """
        @return true if cast operations are not displayed in decompiler output
        """
        ...

    def isPLATECommentIncluded(self) -> bool:
        """
        @return true if Plate comments are included as part of decompiler output
        """
        ...

    def isPOSTCommentIncluded(self) -> bool:
        """
        @return true if Post comments are included as part of decompiler output
        """
        ...

    def isPRECommentIncluded(self) -> bool:
        """
        @return true if Pre comments are included as part of decompiler output
        """
        ...

    def isSimplifyDoublePrecision(self) -> bool:
        """
        If the decompiler currently applies transformation rules that identify and
         simplify double precision arithmetic operations, true is returned.
        @return true if the decompiler applies double precision rules
        """
        ...

    def isWARNCommentIncluded(self) -> bool:
        """
        @return true if WARNING comments are included as part of decompiler output
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def registerOptions(self, fieldOptions: ghidra.framework.options.ToolOptions, opt: ghidra.framework.options.ToolOptions, program: ghidra.program.model.listing.Program) -> None:
        """
        This registers all the decompiler tool options with ghidra, and has the side effect of
         pulling all the current values for the options if they exist
        @param fieldOptions the options object specific to listing fields
        @param opt the options object specific to the decompiler
        @param program the program
        """
        ...

    def setCommentStyle(self, commentStyle: ghidra.app.decompiler.DecompileOptions.CommentStyleEnum) -> None:
        """
        Set the style in which comments are printed as part of decompiler output
        @param commentStyle is the new style to set
        """
        ...

    def setConventionPrint(self, conventionPrint: bool) -> None:
        """
        Set whether the calling convention name should be displayed as part of function signatures
         in decompiler output.
        @param conventionPrint is true if calling convention names should be displayed
        """
        ...

    def setDefaultTimeout(self, timeout: int) -> None:
        """
        Set the maximum time (in seconds) a decompiler process is allowed to analyze a single
         function. If it is exceeded, decompilation is aborted.
        @param timeout is the maximum time in seconds
        """
        ...

    def setDisplayLanguage(self, val: ghidra.program.model.lang.DecompilerLanguage) -> None:
        """
        Set the source programming language that decompiler output should be rendered in.
        @param val is the source language
        """
        ...

    def setEOLCommentIncluded(self, commentEOLInclude: bool) -> None:
        """
        Set whether End-of-line comments are displayed as part of decompiler output.
        @param commentEOLInclude is true if End-of-line comments are output
        """
        ...

    def setEliminateUnreachable(self, eliminateUnreachable: bool) -> None:
        """
        Set whether the decompiler should eliminate unreachable code as part of its analysis.
        @param eliminateUnreachable is true if unreachable code is eliminated
        """
        ...

    def setHeadCommentIncluded(self, commentHeadInclude: bool) -> None:
        """
        Set whether function header comments are included as part of decompiler output.
        @param commentHeadInclude is true if header comments are output
        """
        ...

    def setMaxInstructions(self, num: int) -> None:
        """
        Set the maximum number of assembly instructions in a function to decompile.
         If the number exceeds this, the function is not decompiled.
        @param num is the number of instructions
        """
        ...

    def setMaxJumpTableEntries(self, num: int) -> None:
        """
        Set the maximum number of entries the decompiler will recover from a single jumptable.
         If the number exceeds this, the table is not recovered and control flow from the
         corresponding indirect jump is not followed.
        @param num is the number of entries
        """
        ...

    def setMaxPayloadMBytes(self, mbytes: int) -> None:
        """
        Set the maximum size (in megabytes) of the payload that can be returned by the decompiler
         process when analyzing a single function.  If this size is exceeded, decompilation is
         aborted.
        @param mbytes is the maximum number of megabytes in a function payload
        """
        ...

    def setMaxWidth(self, maxwidth: int) -> None:
        """
        Set the maximum number of characters the decompiler displays in a single line of output
        @param maxwidth is the maximum number of characters
        """
        ...

    def setNameTransformer(self, transformer: ghidra.program.model.symbol.NameTransformer) -> None:
        """
        Set a specific transformer to be applied to all data-type, function, and namespace
         names in decompiler output.  A null value indicates no transform should be applied.
        @param transformer is the transformer to apply
        """
        ...

    def setNoCastPrint(self, noCastPrint: bool) -> None:
        """
        Set whether decompiler output should display cast operations.
        @param noCastPrint is true if casts should NOT be displayed.
        """
        ...

    def setPLATECommentIncluded(self, commentPLATEInclude: bool) -> None:
        """
        Set whether Plate comments are displayed as part of decompiler output
        @param commentPLATEInclude is true if Plate comments are output
        """
        ...

    def setPOSTCommentIncluded(self, commentPOSTInclude: bool) -> None:
        """
        Set whether Post comments are displayed as part of decompiler output
        @param commentPOSTInclude is true if Post comments are output
        """
        ...

    def setPRECommentIncluded(self, commentPREInclude: bool) -> None:
        """
        Set whether Pre comments are displayed as part of decompiler output
        @param commentPREInclude is true if Pre comments are output
        """
        ...

    def setProtoEvalModel(self, protoEvalModel: unicode) -> None:
        """
        Set the default prototype model for the decompiler.  This is the model assumed if no other
         information about a function is known.
        @param protoEvalModel is the name of the prototype model to set as default
        """
        ...

    def setSimplifyDoublePrecision(self, simplifyDoublePrecision: bool) -> None:
        """
        Set whether the decompiler should apply transformation rules that identify and
         simplify double precision arithmetic operations.
        @param simplifyDoublePrecision is true if double precision rules should be applied
        """
        ...

    def setWARNCommentIncluded(self, commentWARNInclude: bool) -> None:
        """
        Set whether automatically generated WARNING comments are displayed as part of
         decompiler output.
        @param commentWARNInclude is true if WARNING comments are output
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
    def EOLCommentIncluded(self) -> bool: ...

    @EOLCommentIncluded.setter
    def EOLCommentIncluded(self, value: bool) -> None: ...

    @property
    def PLATECommentIncluded(self) -> bool: ...

    @PLATECommentIncluded.setter
    def PLATECommentIncluded(self, value: bool) -> None: ...

    @property
    def POSTCommentIncluded(self) -> bool: ...

    @POSTCommentIncluded.setter
    def POSTCommentIncluded(self, value: bool) -> None: ...

    @property
    def PRECommentIncluded(self) -> bool: ...

    @PRECommentIncluded.setter
    def PRECommentIncluded(self, value: bool) -> None: ...

    @property
    def WARNCommentIncluded(self) -> bool: ...

    @WARNCommentIncluded.setter
    def WARNCommentIncluded(self, value: bool) -> None: ...

    @property
    def backgroundColor(self) -> java.awt.Color: ...

    @property
    def cacheSize(self) -> int: ...

    @property
    def commentColor(self) -> java.awt.Color: ...

    @property
    def commentStyle(self) -> ghidra.app.decompiler.DecompileOptions.CommentStyleEnum: ...

    @commentStyle.setter
    def commentStyle(self, value: ghidra.app.decompiler.DecompileOptions.CommentStyleEnum) -> None: ...

    @property
    def constantColor(self) -> java.awt.Color: ...

    @property
    def conventionPrint(self) -> bool: ...

    @conventionPrint.setter
    def conventionPrint(self, value: bool) -> None: ...

    @property
    def currentVariableHighlightColor(self) -> java.awt.Color: ...

    @property
    def defaultColor(self) -> java.awt.Color: ...

    @property
    def defaultFont(self) -> java.awt.Font: ...

    @property
    def defaultTimeout(self) -> int: ...

    @defaultTimeout.setter
    def defaultTimeout(self, value: int) -> None: ...

    @property
    def displayLanguage(self) -> ghidra.program.model.lang.DecompilerLanguage: ...

    @displayLanguage.setter
    def displayLanguage(self, value: ghidra.program.model.lang.DecompilerLanguage) -> None: ...

    @property
    def displayLineNumbers(self) -> bool: ...

    @property
    def eliminateUnreachable(self) -> bool: ...

    @eliminateUnreachable.setter
    def eliminateUnreachable(self, value: bool) -> None: ...

    @property
    def errorColor(self) -> java.awt.Color: ...

    @property
    def functionColor(self) -> java.awt.Color: ...

    @property
    def globalColor(self) -> java.awt.Color: ...

    @property
    def headCommentIncluded(self) -> bool: ...

    @headCommentIncluded.setter
    def headCommentIncluded(self, value: bool) -> None: ...

    @property
    def keywordColor(self) -> java.awt.Color: ...

    @property
    def maxInstructions(self) -> int: ...

    @maxInstructions.setter
    def maxInstructions(self, value: int) -> None: ...

    @property
    def maxJumpTableEntries(self) -> int: ...

    @maxJumpTableEntries.setter
    def maxJumpTableEntries(self, value: int) -> None: ...

    @property
    def maxPayloadMBytes(self) -> int: ...

    @maxPayloadMBytes.setter
    def maxPayloadMBytes(self, value: int) -> None: ...

    @property
    def maxWidth(self) -> int: ...

    @maxWidth.setter
    def maxWidth(self, value: int) -> None: ...

    @property
    def middleMouseHighlightButton(self) -> int: ...

    @property
    def middleMouseHighlightColor(self) -> java.awt.Color: ...

    @property
    def nameTransformer(self) -> ghidra.program.model.symbol.NameTransformer: ...

    @nameTransformer.setter
    def nameTransformer(self, value: ghidra.program.model.symbol.NameTransformer) -> None: ...

    @property
    def noCastPrint(self) -> bool: ...

    @noCastPrint.setter
    def noCastPrint(self, value: bool) -> None: ...

    @property
    def parameterColor(self) -> java.awt.Color: ...

    @property
    def protoEvalModel(self) -> unicode: ...

    @protoEvalModel.setter
    def protoEvalModel(self, value: unicode) -> None: ...

    @property
    def searchHighlightColor(self) -> java.awt.Color: ...

    @property
    def simplifyDoublePrecision(self) -> bool: ...

    @simplifyDoublePrecision.setter
    def simplifyDoublePrecision(self, value: bool) -> None: ...

    @property
    def specialColor(self) -> java.awt.Color: ...

    @property
    def typeColor(self) -> java.awt.Color: ...

    @property
    def variableColor(self) -> java.awt.Color: ...