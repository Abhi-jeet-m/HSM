package com.integra.sign;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.w3c.dom.NodeList;

public class XMLUtilities {

    public static String getEnvelopedXML(String inputXML) {
        XMLSignatureFactory fac = null;
        Reference ref = null;
        SignedInfo si = null;
        KeyPair pair = null;
        KeyInfoFactory kif = null;
        KeyValue kv = null;
        KeyInfo ki = null;
        DocumentBuilderFactory dbf = null;
        Document doc = null;
        DOMSignContext dsc = null;
        XMLSignature signature = null;
        TransformerFactory tf = null;
        Transformer trans = null;
        StringWriter sw = null;
//        String password = "Bangalore@123";
        String password = "shashi";
        String alias = "37ed717e0104ddbdcbd9eb7fd60cdbe927a8d199";
        
        try {

            fac = XMLSignatureFactory.getInstance("DOM");
            ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA256, null), Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);
            si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null), Collections.singletonList(ref));
//			pair = KeyUtil.exportKeyPair();


            KeyStore.PrivateKeyEntry ks = KeyUtil.getKeyFromSmartCardKeyStore(password.toCharArray(), alias);
//            System.out.println("Line79ks:"+ks);


            X509Certificate cert = (X509Certificate) ks.getCertificate();
//            getCertificate("certificate.digital ccb468f0-db77-4f7e-9adc-6a3ecc3fe6a0");

            kif = fac.getKeyInfoFactory();
            List x509Content = new ArrayList();
            x509Content.add(cert.getSubjectX500Principal().getName());
            x509Content.add(cert);
            X509Data xd = kif.newX509Data(x509Content);

            ki = kif.newKeyInfo(Collections.singletonList(xd));
            dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            //doc = dbf.newDocumentBuilder().parse(new FileInputStream(inputXML)); // parse xml file
            doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(inputXML.getBytes("utf-8")));  // parse xml string

            dsc = new DOMSignContext(ks.getPrivateKey(), doc.getDocumentElement());
//            getKey(ConfigListener.aspConf.getAsp_keystore_alias(), ConfigListener.aspConf.getAsp_keystore_password().toCharArray())
            signature = fac.newXMLSignature(si, ki);
            signature.sign(dsc);

            sw = new StringWriter();
            tf = TransformerFactory.newInstance();
            trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(sw));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][NoSuchAlgorithmException] " + e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][InvalidAlgorithmParameterException] " + e.getMessage());
        } catch (FileNotFoundException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][FileNotFoundException] " + e.getMessage());
        } catch (SAXException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][SAXException] " + e.getMessage());
        } catch (IOException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][IOException] " + e.getMessage());
        } catch (ParserConfigurationException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][ParserConfigurationException] " + e.getMessage());
        } catch (MarshalException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][MarshalException] " + e.getMessage());
        } catch (XMLSignatureException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][XMLSignatureException] " + e.getMessage());
        } catch (TransformerConfigurationException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][TransformerConfigurationException] " + e.getMessage());
        } catch (TransformerException e) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][TransformerException] " + e.getMessage());
        } catch (Exception ex) {
            System.out.println("[ESPWebServiceImpl][getEnvelopedXML][Exception] " + ex.getMessage());
        } finally {
            try {
                if (signature != null) {
                    signature = null;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        return sw.toString();
    }

    public static boolean validateXML(String signedXml, PublicKey publicKey) {
        boolean validityStatus = false;
        DocumentBuilderFactory dbf = null;
        Document doc = null;
        NodeList nl = null;
        XMLSignatureFactory fac = null;
        DOMValidateContext valContext = null;

        try {

            dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            //doc = dbf.newDocumentBuilder().parse(new FileInputStream(signedXml));  //to parse xml file
            //doc = dbf.newDocumentBuilder().parse(signedXml); // to parse xml string
            doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(signedXml.getBytes("utf-8")));

//            nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
//            http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
//            	http://www.w3.org/2000/09/xmldsig#
         // Assuming doc is of type org.w3c.dom.Document
            nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
//            nl = findSignatureElements(doc);

            if (nl.getLength() == 0) {
                throw new Exception("Cannot find Signature element");
            }
            // Rest of your code for XML signature processing


//            
            
//            fac = XMLSignatureFactory.getInstance("DOM");
//
//            // Create a DOMValidateContext and specify a KeyValue KeySelector and document context
////			valContext = new DOMValidateContext(KeyUtil.exportKeyPair().getPublic(), nl.item(0));
//            valContext = new DOMValidateContext(publicKey, nl.item(0));

//
//            dbf = DocumentBuilderFactory.newInstance();
//            dbf.setNamespaceAware(true);
//            doc = (Document)dbf.newDocumentBuilder().parse(new ByteArrayInputStream(signedXml.getBytes("utf-8")));
//            nl = ((org.w3c.dom.Document)doc).getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
//            if (nl.getLength() == 0)
//              throw new Exception("Cannot find Signature element"); 
//            fac = XMLSignatureFactory.getInstance("DOM");
//            valContext = new DOMValidateContext(publicKey, nl.item(0));
//            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            
            
            
            fac = XMLSignatureFactory.getInstance("DOM" );
            valContext = new DOMValidateContext(publicKey, nl.item(0));

        
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            
      
            
            
            
            
            
            
            
            
            
            
            
            
            

            
            
            
            
            
            
            
            // Validate the XMLSignature (generated above)
            boolean coreValidity = signature.validate(valContext);

            if (coreValidity == false) {

                System.err.println("Signature failed core validation");
                boolean sv = signature.getSignatureValue().validate(valContext);
                System.out.println("signature validation status: " + sv);
                // check the validation status of each Reference

                @SuppressWarnings("rawtypes")  // suppresses raw type warnings
                Iterator i = signature.getSignedInfo().getReferences().iterator();

                for (int j = 0; i.hasNext(); j++) {
                    boolean refValid = ((Reference) i.next()).validate(valContext);
                    System.out.println("ref[" + j + "] validity status: " + refValid);
                }

            } else {
                validityStatus = true;
                System.out.println("Signature passed core validation");
            }

        } catch (MalformedURLException me) {

            System.out.println("[ESPWebServiceImpl][validateXML][MalformedURLException] " + me.getStackTrace());
        } catch (UnsupportedEncodingException e) {
            System.out.println("[ESPWebServiceImpl][validateXML][UnsupportedEncodingException] " + e.getStackTrace());
        } catch (SAXException e) {
            System.out.println("[ESPWebServiceImpl][validateXML][SAXException] " + e.getStackTrace());
        } catch (IOException e) {
            System.out.println("[ESPWebServiceImpl][validateXML][IOException] " + e.getStackTrace());
        } catch (ParserConfigurationException e) {
            System.out.println("[ESPWebServiceImpl][validateXML][ParserConfigurationException] " + e.getStackTrace());
        } catch (Exception e) {
        	e.printStackTrace();
            System.out.println("[ESPWebServiceImpl][validateXML][Exception] " + e.getStackTrace());
        }
        return validityStatus;
    }
    
    
    
    private static NodeList findSignatureElements(org.w3c.dom.Document document) throws XPathExpressionException {
        XPathFactory xPathFactory = XPathFactory.newInstance();
        XPath xpath = xPathFactory.newXPath();

        // Use the appropriate XPath expression for your document structure
        XPathExpression expr = xpath.compile("//ds:Signature");

        // Assuming ds is the prefix for the XML Digital Signature namespace
        NamespaceContext nsContext = new NamespaceContext() {
            @Override
            public String getNamespaceURI(String prefix) {
                if ("ds".equals(prefix)) {
                    return "http://www.w3.org/2000/09/xmldsig#";
                }
                return null;
            }

            @Override
            public String getPrefix(String namespaceURI) {
                return null;
            }

            @Override
            public Iterator<String> getPrefixes(String namespaceURI) {
                return null;
            }
        };

        xpath.setNamespaceContext(nsContext);

        return (NodeList) expr.evaluate(document, XPathConstants.NODESET);
    }
}
