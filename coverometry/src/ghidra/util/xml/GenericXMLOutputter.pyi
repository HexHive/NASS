from typing import List
import java.io
import java.lang
import org.jdom
import org.jdom.output


class GenericXMLOutputter(org.jdom.output.XMLOutputter):
    """
    A simple extension of XMLOutputter that sets default settings to fix common bugs.
    """

    DEFAULT_INDENT: unicode = u'    '



    def __init__(self):
        """
        This constructor performs basic setup that can be changed later by the user.  For example,
         <pre>
              setTextNormalize( true );
              setIndent( DEFAULT_INDENT );
              setNewlines( true );
         </pre>
        """
        ...



    def clone(self) -> object: ...

    def equals(self, __a0: object) -> bool: ...

    def escapeAttributeEntities(self, __a0: unicode) -> unicode: ...

    def escapeElementEntities(self, __a0: unicode) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def getFormat(self) -> org.jdom.output.Format: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def output(self, __a0: List[object], __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: List[object], __a1: java.io.Writer) -> None: ...

    @overload
    def output(self, __a0: org.jdom.CDATA, __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: org.jdom.CDATA, __a1: java.io.Writer) -> None: ...

    @overload
    def output(self, __a0: org.jdom.Comment, __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: org.jdom.Comment, __a1: java.io.Writer) -> None: ...

    @overload
    def output(self, __a0: org.jdom.DocType, __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: org.jdom.DocType, __a1: java.io.Writer) -> None: ...

    @overload
    def output(self, __a0: org.jdom.Document, __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: org.jdom.Document, __a1: java.io.Writer) -> None: ...

    @overload
    def output(self, __a0: org.jdom.Element, __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: org.jdom.Element, __a1: java.io.Writer) -> None: ...

    @overload
    def output(self, __a0: org.jdom.EntityRef, __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: org.jdom.EntityRef, __a1: java.io.Writer) -> None: ...

    @overload
    def output(self, __a0: org.jdom.ProcessingInstruction, __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: org.jdom.ProcessingInstruction, __a1: java.io.Writer) -> None: ...

    @overload
    def output(self, __a0: org.jdom.Text, __a1: java.io.OutputStream) -> None: ...

    @overload
    def output(self, __a0: org.jdom.Text, __a1: java.io.Writer) -> None: ...

    @overload
    def outputElementContent(self, __a0: org.jdom.Element, __a1: java.io.OutputStream) -> None: ...

    @overload
    def outputElementContent(self, __a0: org.jdom.Element, __a1: java.io.Writer) -> None: ...

    @overload
    def outputString(self, __a0: List[object]) -> unicode: ...

    @overload
    def outputString(self, __a0: org.jdom.CDATA) -> unicode: ...

    @overload
    def outputString(self, __a0: org.jdom.Comment) -> unicode: ...

    @overload
    def outputString(self, __a0: org.jdom.DocType) -> unicode: ...

    @overload
    def outputString(self, __a0: org.jdom.Document) -> unicode: ...

    @overload
    def outputString(self, __a0: org.jdom.Element) -> unicode: ...

    @overload
    def outputString(self, __a0: org.jdom.EntityRef) -> unicode: ...

    @overload
    def outputString(self, __a0: org.jdom.ProcessingInstruction) -> unicode: ...

    @overload
    def outputString(self, __a0: org.jdom.Text) -> unicode: ...

    def setFormat(self, __a0: org.jdom.output.Format) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

