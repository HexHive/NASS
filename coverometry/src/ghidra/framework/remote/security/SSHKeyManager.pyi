import ghidra.security
import java.io
import java.lang
import org.bouncycastle.crypto


class SSHKeyManager(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    @staticmethod
    def getSSHPrivateKey(sshPrivateKeyFile: java.io.File) -> org.bouncycastle.crypto.CipherParameters:
        """
        Return the SSH private key corresponding to the specified key file.
         If the specified key file is encrypted the currently installed password
         provider will be used to obtain the decrypt password.
        @param sshPrivateKeyFile private ssh key file
        @return private key cipher parameters ({@link RSAKeyParameters} or {@link DSAKeyParameters})
        @throws FileNotFoundException key file not found
        @throws IOException if key file not found or key parse failed
        @throws InvalidKeyException if key is not an SSH private key (i.e., PEM format)
        """
        ...

    @overload
    @staticmethod
    def getSSHPrivateKey(sshPrivateKeyIn: java.io.InputStream) -> org.bouncycastle.crypto.CipherParameters:
        """
        Return the SSH private key corresponding to the specified key input stream.
         If the specified key is encrypted the currently installed password
         provider will be used to obtain the decrypt password.
        @param sshPrivateKeyIn private ssh key resource input stream
        @return private key cipher parameters ({@link RSAKeyParameters} or {@link DSAKeyParameters})
        @throws FileNotFoundException key file not found
        @throws IOException if key file not found or key parse failed
        @throws InvalidKeyException if key is not an SSH private key (i.e., PEM format)
        """
        ...

    @staticmethod
    def getSSHPublicKey(sshPublicKeyFile: java.io.File) -> org.bouncycastle.crypto.CipherParameters:
        """
        Attempt to instantiate an SSH public key from the specified file
         which contains a single public key.
        @param sshPublicKeyFile public ssh key file
        @return public key cipher parameters {@link RSAKeyParameters} or {@link DSAKeyParameters}
        @throws FileNotFoundException key file not found
        @throws IOException if key file not found or key parse failed
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def setProtectedKeyStorePasswordProvider(provider: ghidra.security.KeyStorePasswordProvider) -> None:
        """
        Set PKI protected keystore password provider
        @param provider key store password provider
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

