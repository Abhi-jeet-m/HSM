package com.integra.sign;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class KeyUtil {

    //Uncomment the static block for Token sign( For HSM)
    static {
//        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        //Windows
//             String pkcs11Config = "name=eToken\nlibrary=C:\\Windows\\System32\\eps2003csp11v2.dll";
       
        //Linux
      // String pkcs11Config ="name=eToken\nlibrary=/ePass-Linux/ePass2003-Linux-x64/ePass2003-Linux-x64/redist/libcastle.so.1.0.0";
        // UnComment Below 3 lines are for reading Token certificate
//        java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
//        sun.security.pkcs11.SunPKCS11 providerPKCS11 = new sun.security.pkcs11.SunPKCS11(pkcs11ConfigStream);
//        java.security.Security.addProvider(providerPKCS11);
        
        
       
    }

    /*  public static KeyPair exportKeyPair() throws Exception {
     String keystoreFile = ConfigListener.aspConf.getAsp_keystore_path();
     String password = ConfigListener.aspConf.getAsp_keystore_password();
     String alias = ConfigListener.aspConf.getAsp_keystore_alias();

     KeyPair keyPair = null;

     try {

     //             KeyStore keystore=KeyStore.getInstance("JKS");
     KeyStore keystore = KeyStore.getInstance("PKCS12");
     keystore.load(new FileInputStream(keystoreFile), password.toCharArray());
     Key key = keystore.getKey(alias, password.toCharArray());

     if (key instanceof PrivateKey) {

     Certificate cert = keystore.getCertificate(alias);
     PublicKey publicKey = cert.getPublicKey();
     keyPair = new KeyPair(publicKey, (PrivateKey) key);
     }
     } catch (UnrecoverableKeyException e) {
     log.error(e.getMessage());
     } catch (NoSuchAlgorithmException e) {

     log.error(e.getMessage());
     } catch (KeyStoreException e) {

     log.error(e.getMessage());
     }

     return keyPair;
     }
     */
    /*   public static KeyStore exportKeyStore() throws Exception {
     String keystoreFile = ConfigListener.aspConf.getAsp_keystore_path();
     String password = ConfigListener.aspConf.getAsp_keystore_password();
     String alias = ConfigListener.aspConf.getAsp_keystore_alias();
     KeyStore keystore = null;

     try {
     keystore = KeyStore.getInstance("PKCS12");
     keystore.load(new FileInputStream(keystoreFile), password.toCharArray());
     } catch (KeyStoreException e) {

     log.error(e.getMessage());
     }
     return keystore;
     }*/
    public static PublicKey getCertificateFromFile(String certificateFile) throws GeneralSecurityException, IOException {
        FileInputStream fis = null;
        PublicKey publicKey = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
            fis = new FileInputStream(certificateFile);
            X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(fis);

            publicKey = x509Certificate.getPublicKey();
//        return (X509Certificate) certFactory.generateCertificate(fis);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        return publicKey;
    }

    public static KeyStore.PrivateKeyEntry getKeyFromSmartCardKeyStore(char[] smartCardPin, String alias) throws Exception {
        System.out.println("[DigitalSigner][getKeyFromSmartCardKeyStore][PREPARING KEY ENTRY FROM SMARTCARD]");
        // Load the KeyStore and get the signing key and certificate.
        KeyStore.PrivateKeyEntry entry = null;
        try {
             //char[] pin = smartCardPin.toCharArray();

            // UnComment Below 2 lines are for Token Program
//            KeyStore keyStore = KeyStore.getInstance("PKCS11");
//            keyStore.load(null, smartCardPin);
            
            
            //UnComment Below 5 lines for Self signed Certificate
            //Below are the code for Self Signed certificate

 
        	String pkcs11Config = "IntegraUAT-self.p12";
             BouncyCastleProvider bcp = new BouncyCastleProvider();
             Security.insertProviderAt(bcp, 1);
  

          // Register Bouncy Castle as a security provider
          Security.addProvider(new BouncyCastleProvider());
             KeyStore keyStore = KeyStore.getInstance("PKCS12");
//          String password ="";
         keyStore.load(new FileInputStream(pkcs11Config), "Integra".toCharArray());
             alias = keyStore.aliases().nextElement();
              
            KeyStore.ProtectionParameter entryPassword  = new KeyStore.PasswordProtection("Integra".toCharArray());
        
                      if (keyStore.isKeyEntry(alias)) {
                          entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, entryPassword);
                      } else {
                    
                          throw new Exception("Invalid alias name. No private key found with the given alias name in smart card keystore.");
                      }
        } catch (Exception ex) {
       
        	ex.printStackTrace();
        
//            System.out.println("[DigitalSigner][getKeyFromSmartCardKeyStore][Exception]" + ex.getMessage());
//            throw new Exception("Invalid alias name. No private key found with the given alias name in smart card keystore.");
        }
        return entry;
    }
}
