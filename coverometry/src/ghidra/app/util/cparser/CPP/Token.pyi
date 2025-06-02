import ghidra.app.util.cparser.CPP
import java.io
import java.lang


class Token(object, java.io.Serializable):
    """
    Describes the input token stream.
    """

    beginColumn: int
    beginLine: int
    endColumn: int
    endLine: int
    image: unicode
    kind: int
    next: ghidra.app.util.cparser.CPP.Token
    specialToken: ghidra.app.util.cparser.CPP.Token



    @overload
    def __init__(self):
        """
        No-argument constructor
        """
        ...

    @overload
    def __init__(self, kind: int):
        """
        Constructs a new token for the specified Image.
        """
        ...

    @overload
    def __init__(self, kind: int, image: unicode):
        """
        Constructs a new token for the specified Image and Kind.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getValue(self) -> object:
        """
        An optional attribute value of the Token.
         Tokens which are not used as syntactic sugar will often contain
         meaningful values that will be used later on by the compiler or
         interpreter. This attribute value is often different from the image.
         Any subclass of Token that actually wants to return a non-null value can
         override this method as appropriate.
        """
        ...

    def hashCode(self) -> int: ...

    @overload
    @staticmethod
    def newToken(ofKind: int) -> ghidra.app.util.cparser.CPP.Token: ...

    @overload
    @staticmethod
    def newToken(ofKind: int, image: unicode) -> ghidra.app.util.cparser.CPP.Token:
        """
        Returns a new Token object, by default. However, if you want, you
         can create and return subclass objects based on the value of ofKind.
         Simply add the cases to the switch for all those special cases.
         For example, if you have a subclass of Token called IDToken that
         you want to create if ofKind is ID, simply add something like :

            case MyParserConstants.ID : return new IDToken(ofKind, image);

         to the following switch statement. Then you can cast matchedToken
         variable to the appropriate type and use sit in your lexical actions.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode:
        """
        Returns the image.
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def value(self) -> object: ...