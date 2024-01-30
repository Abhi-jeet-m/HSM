package com.integra.jsignusbtoken.utilities;

import com.integra.jsignusbtoken.utilities.EncryptDecrypt;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.Properties;

public class Properties_Loader {
  public static String TOKEN_CONFIG_PATH;
  
  public static String TOKEN_ALIAS;
  
  public static String TOKEN_PASSWORD;
  
  public static String TOKEN_SIGN_ENABLE;
  
  public static void loadProperties() {
    setTOKEN_ALIAS(EncryptDecrypt.decrypt(getValueFromPropetyFile("token.alias")));
    setTOKEN_CONFIG_PATH(EncryptDecrypt.decrypt(getValueFromPropetyFile("token.config.path")));
    setTOKEN_PASSWORD(EncryptDecrypt.decrypt(getValueFromPropetyFile("token.password")));
    setTOKEN_SIGN_ENABLE(getValueFromPropetyFile("token.sign.enable"));
  }
  
  public static String getValueFromPropetyFile(String StrLabel) {
    Properties props = null;
    String returnvalue = null;
    try {
      props = new Properties();
      props.load(new InputStreamReader(new FileInputStream("jsignUSBToken.properties")));
      returnvalue = props.getProperty(StrLabel);
    } catch (Exception ex) {
      System.out.println("[Properties_Loader][getValueFromPropetyFile][Exception]Key Missing: " + StrLabel + " " + ex
          .getMessage());
    } 
    return returnvalue;
  }
  
  public static String getTOKEN_CONFIG_PATH() {
    return TOKEN_CONFIG_PATH;
  }
  
  public static String getTOKEN_ALIAS() {
    return TOKEN_ALIAS;
  }
  
  public static String getTOKEN_PASSWORD() {
    return TOKEN_PASSWORD;
  }
  
  public static void setTOKEN_CONFIG_PATH(String tOKEN_CONFIG_PATH) {
    TOKEN_CONFIG_PATH = tOKEN_CONFIG_PATH;
  }
  
  public static void setTOKEN_ALIAS(String tOKEN_ALIAS) {
    TOKEN_ALIAS = tOKEN_ALIAS;
  }
  
  public static void setTOKEN_PASSWORD(String tOKEN_PASSWORD) {
    TOKEN_PASSWORD = tOKEN_PASSWORD;
  }
  
  public static String getTOKEN_SIGN_ENABLE() {
    return TOKEN_SIGN_ENABLE;
  }
  
  public static void setTOKEN_SIGN_ENABLE(String tOKEN_SIGN_ENABLE) {
    TOKEN_SIGN_ENABLE = tOKEN_SIGN_ENABLE;
  }
}
