package BOOTINF.classes.com.integra.jsignusbtoken;

import com.integra.jsignusbtoken.utilities.Properties_Loader;


import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;
import javax.servlet.http.HttpServletRequest;
import org.apache.tomcat.util.codec.binary.Base64;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = {"*"})
public class WSController {
  @PostMapping(value = {"/TOKENSIGN/getDSCTokenSign"}, consumes = {"application/JSON"}, produces = {"application/JSON"})
  public String getDSCTokenSign(@RequestBody String tokenInfo, HttpServletRequest requestContext) throws JSONException, UnsupportedEncodingException {
    System.out.println("In getDSCTokenSign External Service ");
    String ip = requestContext.getRemoteAddr();
    JSONObject jsRes = new JSONObject();
    JSONObject input = new JSONObject(tokenInfo);
    String status = "FAILED";
    String encodedBase64SignedHash = null;
    
    System.out.println("input to hsm:"+tokenInfo);
    
    try {
      String password = Properties_Loader.getTOKEN_PASSWORD();
      String configPath = Properties_Loader.getTOKEN_CONFIG_PATH();
      String alias = Properties_Loader.getTOKEN_ALIAS();
      byte[] pdfbyte = Base64.decodeBase64(input.getString("docHash"));
      JSONObject js = PDFUSBTokenSign.presetup(configPath, password, alias);
      if (js.getString("status").equalsIgnoreCase("SUCCESS")) {
        byte[] signedHash = PDFUSBTokenSign.sign(pdfbyte);
//        encodedBase64SignedHash = new String(Base64.encodeBase64(signedHash, true));
        encodedBase64SignedHash = new String(java.util.Base64.getEncoder().encode(signedHash));
        jsRes.put("status", "SUCCESS");
        jsRes.put("signerName", PDFUSBTokenSign.certName);
        jsRes.put("signedHash", encodedBase64SignedHash);
        jsRes.put("statusDetails", "Doc Hash sign completed");
        status = "SIGNED";
      } else {
        jsRes.put("status", "FAILED");
        jsRes.put("statusDetails", js.getString("statusDetails"));
      } 
    } catch (JSONException|java.io.FileNotFoundException e1) {
      e1.printStackTrace();
      status = e1.getMessage();
    } catch (IOException e1) {
      e1.printStackTrace();
      status = e1.getMessage();
    } catch (InvalidKeyException e1) {
      e1.printStackTrace();
      status = e1.getMessage();
    } catch (NoSuchAlgorithmException e1) {
      e1.printStackTrace();
      status = e1.getMessage();
    } catch (SignatureException e1) {
      e1.printStackTrace();
      status = e1.getMessage();
    } finally {
      try {
        FileWriter writer = new FileWriter("DSC_Token_Sign_Log.txt", true);
        BufferedWriter bufferedWriter = new BufferedWriter(writer);
        bufferedWriter.write("Username-" + input.getString("username") + "|TxnID-" + input.getString("txnid") + "|DocHash-" + input
            .getString("docHash") + "|Date-" + new Date() + "|Status-" + status);
        bufferedWriter.newLine();
        bufferedWriter.close();
      } catch (IOException e) {
        e.printStackTrace();
      } 
    } 
    return jsRes.toString();
  }
  

    @PostMapping(value = {"/HSM/getXMLSigned"}, consumes = {"application/JSON"}, produces = {"application/JSON"})
    public String getXMLSigned(@RequestBody String tokenInfo, HttpServletRequest requestContext) throws JSONException, UnsupportedEncodingException {
     
    	
    	String ip = requestContext.getRemoteAddr();
      JSONObject js = new JSONObject();
      JSONObject jsRes = new JSONObject();
      JSONObject input = new JSONObject(tokenInfo);

      try {
    	  System.out.println("inside  getXMLSigned");
      	jsRes=ClientHandler.presetup(input);

      } catch (Exception ex) {
      	ex.printStackTrace();
       
      } 
      return jsRes.toString();
    }
}
