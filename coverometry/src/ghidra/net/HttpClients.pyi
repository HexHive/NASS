import java.lang
import java.net.http
import java.net.http.HttpClient


class HttpClients(object):




    def __init__(self): ...



    @staticmethod
    def clearHttpClient() -> None:
        """
        Clears the currently cached {@link HttpClient}, forcing it to be
         rebuilt during the next call to {@link #getHttpClient()}.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getHttpClient() -> java.net.http.HttpClient:
        """
        Returns a shared, plain (no special options) {@link HttpClient}.
        @return a {@link HttpClient}
        @throws IOException if error in PKI settings or crypto configuration
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def newHttpClientBuilder() -> java.net.http.HttpClient.Builder:
        """
        Creates a HttpClient Builder using Ghidra SSL/TLS context info.
        @return a new HttpClient Builder
        @throws IOException if error in PKI settings or crypto configuration
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

