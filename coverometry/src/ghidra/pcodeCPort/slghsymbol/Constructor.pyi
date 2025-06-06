import generic.stl
import ghidra.pcodeCPort.semantics
import ghidra.pcodeCPort.sleighbase
import ghidra.pcodeCPort.slghpatexpress
import ghidra.pcodeCPort.slghsymbol
import java.io
import java.lang
import java.util
import org.jdom


class Constructor(object):
    location: ghidra.sleigh.grammar.Location



    @overload
    def __init__(self, __a0: ghidra.sleigh.grammar.Location): ...

    @overload
    def __init__(self, __a0: ghidra.sleigh.grammar.Location, __a1: ghidra.pcodeCPort.slghsymbol.SubtableSymbol): ...



    def addContext(self, __a0: generic.stl.VectorSTL) -> None: ...

    def addEquation(self, __a0: ghidra.pcodeCPort.slghpatexpress.PatternEquation) -> None: ...

    def addInvisibleOperand(self, __a0: ghidra.pcodeCPort.slghsymbol.OperandSymbol) -> None: ...

    def addOperand(self, __a0: ghidra.pcodeCPort.slghsymbol.OperandSymbol) -> None: ...

    def addSyntax(self, __a0: unicode) -> None: ...

    def collectLocalExports(self, __a0: java.util.ArrayList) -> None: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFilename(self) -> unicode: ...

    def getId(self) -> long: ...

    def getIndex(self) -> int: ...

    def getLineno(self) -> int: ...

    def getMinimumLength(self) -> int: ...

    def getNamedTempl(self, __a0: int) -> ghidra.pcodeCPort.semantics.ConstructTpl: ...

    def getNumOperands(self) -> int: ...

    def getNumSections(self) -> int: ...

    def getOperand(self, __a0: int) -> ghidra.pcodeCPort.slghsymbol.OperandSymbol: ...

    def getParent(self) -> ghidra.pcodeCPort.slghsymbol.SubtableSymbol: ...

    def getPattern(self) -> ghidra.pcodeCPort.slghpatexpress.TokenPattern: ...

    def getPatternEquation(self) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation: ...

    def getTempl(self) -> ghidra.pcodeCPort.semantics.ConstructTpl: ...

    def hashCode(self) -> int: ...

    def isError(self) -> bool: ...

    def isRecursive(self) -> bool: ...

    def markSubtableOperands(self, __a0: generic.stl.VectorSTL) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def printInfo(self, __a0: java.io.PrintStream) -> None: ...

    def removeTrailingSpace(self) -> None: ...

    def restoreXml(self, __a0: org.jdom.Element, __a1: ghidra.pcodeCPort.sleighbase.SleighBase) -> None: ...

    def saveXml(self, __a0: java.io.PrintStream) -> None: ...

    def setError(self, __a0: bool) -> None: ...

    def setId(self, __a0: long) -> None: ...

    def setMainSection(self, __a0: ghidra.pcodeCPort.semantics.ConstructTpl) -> None: ...

    def setMinimumLength(self, __a0: int) -> None: ...

    def setNamedSection(self, __a0: ghidra.pcodeCPort.semantics.ConstructTpl, __a1: int) -> None: ...

    def setSourceFileIndex(self, __a0: int) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def error(self) -> bool: ...

    @error.setter
    def error(self, value: bool) -> None: ...

    @property
    def filename(self) -> unicode: ...

    @property
    def id(self) -> long: ...

    @id.setter
    def id(self, value: long) -> None: ...

    @property
    def index(self) -> int: ...

    @property
    def lineno(self) -> int: ...

    @property
    def mainSection(self) -> None: ...  # No getter available.

    @mainSection.setter
    def mainSection(self, value: ghidra.pcodeCPort.semantics.ConstructTpl) -> None: ...

    @property
    def minimumLength(self) -> int: ...

    @minimumLength.setter
    def minimumLength(self, value: int) -> None: ...

    @property
    def numOperands(self) -> int: ...

    @property
    def numSections(self) -> int: ...

    @property
    def parent(self) -> ghidra.pcodeCPort.slghsymbol.SubtableSymbol: ...

    @property
    def pattern(self) -> ghidra.pcodeCPort.slghpatexpress.TokenPattern: ...

    @property
    def patternEquation(self) -> ghidra.pcodeCPort.slghpatexpress.PatternEquation: ...

    @property
    def recursive(self) -> bool: ...

    @property
    def sourceFileIndex(self) -> None: ...  # No getter available.

    @sourceFileIndex.setter
    def sourceFileIndex(self, value: int) -> None: ...

    @property
    def templ(self) -> ghidra.pcodeCPort.semantics.ConstructTpl: ...