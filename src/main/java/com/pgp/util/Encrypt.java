package com.pgp.util;

import lombok.Data;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.IOException;

@Data
public class Encrypt {

  private boolean isArmored;
  private boolean isSigning;
  private boolean checkIntegrity;
  private String publicKeyFilePath;
  private PGPPublicKey publicKey;
  private PGPPrivateKey privateKey;
  private PGPSecretKey secretKey;


  private String privateKeyFilePath;
  private char[] privateKeyPassword;

  public void setPublicKeyFilePath(String publicKeyFilePath) throws IOException, PGPException {
    this.publicKeyFilePath = publicKeyFilePath;
    publicKey = BCPGPUtils.readPublicKey(publicKeyFilePath);
  }

}
