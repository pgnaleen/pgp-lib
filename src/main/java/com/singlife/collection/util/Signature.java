package com.singlife.collection.util;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.security.Provider;
import java.security.Security;

public class Signature {

  private Encrypt encrypt;

  private static Provider getProvider() {
    Provider provider = Security.getProvider("BC");
    if (provider == null) {
      provider = new BouncyCastleProvider();
      Security.addProvider(provider);
    }
    return provider;
  }

  public Signature(Encrypt encrypt) throws IOException, PGPException {
    this.encrypt = encrypt;
    encrypt.setPublicKey(BCPGPUtils.readPublicKey(encrypt.getPublicKeyFilePath()));

    PGPSecretKey secretKey = BCPGPUtils.readSecretKey(encrypt.getPrivateKeyFilePath());
    encrypt.setSecretKey(secretKey);

    PGPPrivateKey privateKey = secretKey
        .extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
            .build(encrypt.getPrivateKeyPassword()));
    encrypt.setPrivateKey(privateKey);
    this.encrypt = encrypt;

  }

  public String signatureGenerate(String queryParams, String privateKeyFile)
      throws IOException, PGPException {

    final byte[] message = queryParams.getBytes();
    ByteArrayOutputStream encOut = new ByteArrayOutputStream();
    OutputStream out = encOut;
    out = new ArmoredOutputStream(out);

    PGPSecretKey pgpSec = BCPGPUtils.readSecretKey(privateKeyFile);

    PGPPrivateKey pgpPrivKey = pgpSec
        .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
            .setProvider(getProvider())
            .build(encrypt.getPrivateKeyPassword()));
    PGPSignatureGenerator sGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(
        encrypt.getSecretKey().getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256));

    sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

    BCPGOutputStream bOut = new BCPGOutputStream(out);

    InputStream fIn = new ByteArrayInputStream(message);

    int ch;
    while ((ch = fIn.read()) >= 0) {
      sGen.update((byte) ch);
    }

    fIn.close();
    sGen.generate().encode(bOut);
    out.close();

    return encOut.toString();

  }

}

