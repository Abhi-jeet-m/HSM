package com.integra.jsignusbtoken.utilities;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

//import jakarta.xml.bind.DatatypeConverter;

public class EncryptDecrypt {
  private static final String password = "ThisIsASecretKeYforRateCard";
  
  public static String encrypt(String str) {
    try {
      SecureRandom random = new SecureRandom();
      byte[] salt = new byte[16];
      random.nextBytes(salt);
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      KeySpec spec = new PBEKeySpec("ThisIsASecretKeYforRateCard".toCharArray(), salt, 65536, 256);
      SecretKey tmp = factory.generateSecret(spec);
      SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(1, secret);
      AlgorithmParameters params = cipher.getParameters();
      byte[] iv = ((IvParameterSpec)params.<IvParameterSpec>getParameterSpec(IvParameterSpec.class)).getIV();
      byte[] encryptedText = cipher.doFinal(str.getBytes("UTF-8"));
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      outputStream.write(salt);
      outputStream.write(iv);
      outputStream.write(encryptedText);
      return Base64.getEncoder().encodeToString(DatatypeConverter.printBase64Binary(outputStream.toByteArray()).getBytes());
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    } 
  }
  
  public static String decrypt(String str) {
    try {
      byte[] ciphertext = DatatypeConverter.parseBase64Binary(new String(Base64.getDecoder().decode(str)));
      if (ciphertext.length < 48)
        return null; 
      byte[] salt = Arrays.copyOfRange(ciphertext, 0, 16);
      byte[] iv = Arrays.copyOfRange(ciphertext, 16, 32);
      byte[] ct = Arrays.copyOfRange(ciphertext, 32, ciphertext.length);
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      KeySpec spec = new PBEKeySpec("ThisIsASecretKeYforRateCard".toCharArray(), salt, 65536, 256);
      SecretKey tmp = factory.generateSecret(spec);
      SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(2, secret, new IvParameterSpec(iv));
      byte[] plaintext = cipher.doFinal(ct);
      return new String(plaintext, "UTF-8");
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    } 
  }
}
