/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package BOOTINF.classes.com.integra.jsignusbtoken;

import com.integra.sign.KeyUtil;
import com.integra.sign.XMLUtilities;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.json.JSONObject;

/**
 *
 * @author debashishrout
 */
//public class ClientHandler extends Thread {
public class ClientHandler  {


	public static JSONObject  presetup(JSONObject inputs) {
            try {

            	String password = "shashi";
                String alias = "37ed717e0104ddbdcbd9eb7fd60cdbe927a8d199";
          
                String out = XMLUtilities.getEnvelopedXML(inputs.getString("esignXMLString"));
                 
                Boolean res = XMLUtilities.validateXML(out, KeyUtil.getKeyFromSmartCardKeyStore(password.toCharArray(), alias).getCertificate().getPublicKey());
      
                System.out.println("res:"+res);
                
                if (res) {
                    out = "T" + out;
                    inputs.put("status","SUCCESS" );
                } else {
                    out = "F" + out;
                    inputs.put("status","FAILURE");
                }
                inputs.put("esignXMLString", out);
                
            } catch (Exception ex) {
            	ex.printStackTrace();
                System.out.println("[ClientHandler][run] Exception :" + ex.getMessage());
                System.out.println("[ClientHandler][run] Exception Cause:" + ex.getCause());
                System.out.println("[ClientHandler][run] Exception StackTrace:" + ex.getStackTrace());
            }
           
			return inputs;
    }
    
    
}
