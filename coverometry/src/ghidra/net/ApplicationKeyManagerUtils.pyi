from typing import List
import ghidra.net
import java.io
import java.lang
import java.security
import java.security.KeyStore
import java.security.cert
import java.util
import javax.security.auth.x500


class ApplicationKeyManagerUtils(object):
    """
    ApplicationKeyManagerUtils provides public methods for utilizing
     the application PKI key management, including access to trusted issuers
     (i.e., CA certificates), token signing and validation, and the ability to
     generate keystores for testing or when a self-signed certificate will
     suffice.
    """

    BEGIN_CERT: unicode = u'-----BEGIN CERTIFICATE-----'
    END_CERT: unicode = u'-----END CERTIFICATE-----'
    PKCS_FILENAME_FILTER: javax.swing.filechooser.FileNameExtensionFilter = javax.swing.filechooser.FileNameExtensionFilter@2927bb63[description=PKCS Key File extensions=[p12, pks, pfx]]
    PKCS_FILE_EXTENSIONS: List[unicode] = array(java.lang.String, [u'p12', u'pks', u'pfx'])
    RSA_TYPE: unicode = u'RSA'







    @staticmethod
    def createKeyEntry(alias: unicode, dn: unicode, durationDays: int, caEntry: java.security.KeyStore.PrivateKeyEntry, keyFile: java.io.File, keystoreType: unicode, subjectAlternativeNames: java.util.Collection, protectedPassphrase: List[int]) -> java.security.KeyStore.PrivateKeyEntry:
        """
        Generate a new {@link X509Certificate} with RSA {@link KeyPair} and create/update a {@link KeyStore}
         optionally backed by a keyFile.
        @param alias entry alias with keystore
        @param dn distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
        @param durationDays number of days which generated certificate should remain valid
        @param caEntry optional CA private key entry.  If null, a self-signed CA certificate will be generated.
        @param keyFile optional file to load/store resulting {@link KeyStore} (may be null)
        @param keystoreType support keystore type (e.g., "JKS", "PKCS12")
        @param subjectAlternativeNames an optional list of subject alternative names to be included 
         			in certificate (may be null)
        @param protectedPassphrase key and keystore protection password
        @return newly generated keystore entry with key pair
        @throws KeyStoreException if error occurs while updating keystore
        """
        ...

    @staticmethod
    def createKeyStore(alias: unicode, dn: unicode, durationDays: int, caEntry: java.security.KeyStore.PrivateKeyEntry, keyFile: java.io.File, keystoreType: unicode, subjectAlternativeNames: java.util.Collection, protectedPassphrase: List[int]) -> java.security.KeyStore:
        """
        Generate a new {@link X509Certificate} with RSA {@link KeyPair} and create/update a {@link KeyStore}
         optionally backed by a keyFile.
        @param alias entry alias with keystore
        @param dn distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
        @param durationDays number of days which generated certificate should remain valid
        @param caEntry optional CA private key entry.  If null, a self-signed CA certificate will be 
         			generated.
        @param keyFile optional file to load/store resulting {@link KeyStore} (may be null)
        @param keystoreType support keystore type (e.g., "JKS", "PKCS12")
        @param subjectAlternativeNames an optional list of subject alternative names to be included 
         			in certificate (may be null)
        @param protectedPassphrase key and keystore protection password
        @return keystore containing newly generated certification with key pair
        @throws KeyStoreException if error occurs while updating keystore
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def exportX509Certificates(certificates: List[java.security.cert.Certificate], outFile: java.io.File) -> None:
        """
        Export X.509 certificates to the specified outFile.
        @param certificates certificates to be stored
        @param outFile output file
        @throws IOException if error occurs writing to outFile
        @throws CertificateEncodingException if error occurs while encoding certificate data
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getSignedToken(authorities: List[java.security.Principal], token: List[int]) -> ghidra.net.SignedToken:
        """
        Sign the supplied token byte array using an installed certificate from
         one of the specified authorities
        @param authorities trusted certificate authorities
        @param token token byte array
        @return signed token object
        @throws NoSuchAlgorithmException algorithym associated within signing certificate not found
        @throws SignatureException failed to generate SignedToken
        @throws CertificateException error associated with signing certificate
        """
        ...

    @staticmethod
    def getTrustedIssuers() -> List[javax.security.auth.x500.X500Principal]:
        """
        Returns a list of trusted issuers (i.e., CA certificates) as established
         by the {@link ApplicationTrustManagerFactory}.
        @return array of trusted Certificate Authorities
        @throws CertificateException if failed to properly initialize trust manager
         due to CA certificate error(s).
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isMySignature(authorities: List[java.security.Principal], token: List[int], signature: List[int]) -> bool:
        """
        Verify that the specified sigBytes reflect my signature of the specified
         token.
        @param authorities trusted certificate authorities
        @param token byte array token
        @param signature token signature
        @return true if signature is my signature
        @throws NoSuchAlgorithmException algorithym associated within signing certificate not found
        @throws SignatureException failed to generate SignedToken
        @throws CertificateException error associated with signing certificate
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def validateClient(certChain: List[java.security.cert.X509Certificate], authType: unicode) -> None:
        """
        Validate a client certificate ensuring that it is not expired and is
         trusted based upon the active trust managers.
        @param certChain X509 certificate chain
        @param authType authentication type (i.e., "RSA")
        @throws CertificateException if certificate validation fails
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

