package BOOTINF.classes.com.integra.jsignusbtoken;

import com.integra.jsignusbtoken.utilities.Properties_Loader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;
import org.json.JSONException;
import org.json.JSONObject;
//import sun.security.pkcs11.SunPKCS11;

public class PDFUSBTokenSign {
  static KeyStore ks = null;
  
  static PrivateKey pk = null;
  
  static Certificate[] chain = null;
  
  static BouncyCastleProvider bcp = null;
  
  static String certName = null;
  
  public static JSONObject presetup(String configPath, String password, String alias) {
    JSONObject jsRes = new JSONObject();
    try {
      if (Properties_Loader.TOKEN_SIGN_ENABLE.equalsIgnoreCase("ture")) {
        ByteArrayInputStream pkcs11ConfigStream = new ByteArrayInputStream(configPath.getBytes());
//        SunPKCS11 providerPKCS11 = new SunPKCS11(pkcs11ConfigStream);
//        Security.addProvider(providerPKCS11);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password.toCharArray());
        Certificate certificate = keyStore.getCertificate(alias);
        X500Name x500name = (new JcaX509CertificateHolder((X509Certificate)certificate)).getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        RDN pincode = x500name.getRDNs(BCStyle.POSTAL_CODE)[0];
        RDN st = x500name.getRDNs(BCStyle.ST)[0];
        certName = IETFUtils.valueToString(cn.getFirst().getValue());
        String pinCode = IETFUtils.valueToString(pincode.getFirst().getValue());
        String state = IETFUtils.valueToString(st.getFirst().getValue());
        KeyStore.PrivateKeyEntry entry = null;
        if (keyStore.isKeyEntry(alias)) {
          entry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
        } else {
          throw new Exception("Invalid alias name. No private key found with the given alias name in smart card keystore.");
        } 
        pk = entry.getPrivateKey();
        chain = keyStore.getCertificateChain(alias);
        bcp = new BouncyCastleProvider();
        Security.insertProviderAt((Provider)bcp, 1);
        jsRes.put("status", "SUCCESS");
        jsRes.put("statusDetails", "E-Token Exixts");
        jsRes.put("cn", certName);
        jsRes.put("pinCode", pinCode);
        jsRes.put("state", state);
      } else {
    	  password="Integra";
        bcp = new BouncyCastleProvider();
        Security.insertProviderAt((Provider)bcp, 1);
        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("IntegraUAT-self.p12"), password.toCharArray());
        String alias1 = ks.aliases().nextElement();
        System.out.println("alias1 : " + alias1);
        pk = (PrivateKey)ks.getKey(alias1, password.toCharArray());
        chain = ks.getCertificateChain(alias1);
        certName = "Integra Micro System Pvt. Ltd.";
        jsRes.put("status", "SUCCESS");
        jsRes.put("statusDetails", "Self signed certificate");
        jsRes.put("cn", certName);
        jsRes.put("pinCode", "");
        jsRes.put("state", "Karnataka");
        
      } 
    } catch (Exception e) {
      e.printStackTrace();
      try {
        jsRes.put("status", "FAILURE");
        jsRes.put("statusDetails", "E-Token NOT present");
        jsRes.put("errorMsg", e.getMessage());
      } catch (JSONException e1) {
        e1.printStackTrace();
      } 
    } 
    return jsRes;
  }
  
  public static byte[] sign(byte[] hash) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    try {
      PrivateKey privKey = pk;
      List<Certificate> certList = new ArrayList<>();
      certList.addAll(Arrays.asList(chain));
      JcaCertStore certs = new JcaCertStore(certList);
      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      Attribute attr = new Attribute(CMSAttributes.messageDigest, (ASN1Set)new DERSet((ASN1Encodable)new DEROctetString(hash)));
      ASN1EncodableVector v = new ASN1EncodableVector();
      v.add((ASN1Encodable)attr);
      SignerInfoGeneratorBuilder builder = (new SignerInfoGeneratorBuilder((DigestCalculatorProvider)new BcDigestCalculatorProvider())).setSignedAttributeGenerator((CMSAttributeTableGenerator)new DefaultSignedAttributeTableGenerator(new AttributeTable(v)));
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      InputStream in = new ByteArrayInputStream(chain[0].getEncoded());
      X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
      ContentSigner sha256Signer = (new JcaContentSignerBuilder("SHA256WithRSA")).build(privKey);
      gen.addSignerInfoGenerator(builder.build(sha256Signer, (X509CertificateHolder)new JcaX509CertificateHolder(cert)));
      gen.addCertificates((Store)certs);
      CMSSignedData s = gen.generate((CMSTypedData)new CMSAbsentContent(), false);
      return s.getEncoded();
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } catch (CMSException e) {
      throw new IOException(e);
    } catch (OperatorCreationException e) {
      throw new IOException(e);
    } 
  }
}
