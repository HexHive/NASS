from typing import List
import java.io
import java.lang


class ObfuscatedInputStream(java.io.InputStream):
    """
    An InputStream wrapper that de-obfuscates the bytes being read from the underlying
     stream.
    """





    def __init__(self, delegate: java.io.InputStream):
        """
        Creates instance.
        @param delegate {@link InputStream} to wrap
        """
        ...



    def available(self) -> int: ...

    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def main(args: List[unicode]) -> None:
        """
        Entry point to enable command line users to retrieve the contents of an obfuscated
         file.
        @param args either ["--help"], or [ "input_filename", "output_filename" ]
        @throws IOException if error
        """
        ...

    def mark(self, __a0: int) -> None: ...

    def markSupported(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def nullInputStream() -> java.io.InputStream: ...

    @overload
    def read(self) -> int: ...

    @overload
    def read(self, __a0: List[int]) -> int: ...

    @overload
    def read(self, b: List[int], off: int, len: int) -> int: ...

    def readAllBytes(self) -> List[int]: ...

    @overload
    def readNBytes(self, __a0: int) -> List[int]: ...

    @overload
    def readNBytes(self, __a0: List[int], __a1: int, __a2: int) -> int: ...

    def reset(self) -> None: ...

    def skip(self, __a0: long) -> long: ...

    def skipNBytes(self, __a0: long) -> None: ...

    def toString(self) -> unicode: ...

    def transferTo(self, __a0: java.io.OutputStream) -> long: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

