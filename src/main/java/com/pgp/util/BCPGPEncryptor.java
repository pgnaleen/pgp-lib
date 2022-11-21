package com.pgp.util;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

public class BCPGPEncryptor {

  private static final Logger LOGGER = LoggerFactory.getLogger(BCPGPEncryptor.class);
  private Encrypt encrypt;

  private static Provider getProvider() {
    Provider provider = Security.getProvider("BC");
    if (provider == null) {
      provider = new BouncyCastleProvider();
      Security.addProvider(provider);
    }
    return provider;
  }


  public BCPGPEncryptor(Encrypt encrypt) throws IOException, PGPException {
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


  public String encryptMessage(String message) throws PGPException, IOException {
    if (encrypt.isSigning()) {
      byte[] encryptedMsgByte = encryptAndSignMessage(
          message.getBytes("UTF-8"),
          encrypt.getPublicKeyFilePath(),
          encrypt.getPrivateKeyFilePath(),
          encrypt.getPrivateKeyPassword()
      );
      final String encryptedMsg = new String(encryptedMsgByte);
      return encryptedMsg;
    } else {
      return "Without Signing not supported";
    }
  }


  public byte[] encryptAndSignMessage(
      final byte[] message, String publicKeyFile, String privateKeyFile,
      char[] passPhrase
  ) throws PGPException {
    getProvider();
    try {
      LOGGER.info("message:::" + message);
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
          new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
              .setWithIntegrityPacket(true)
              .setSecureRandom(new SecureRandom()));



      encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encrypt.getPublicKey())
          .setSecureRandom(new SecureRandom()));

      final OutputStream theOut = encrypt.isArmored() ? new ArmoredOutputStream(out) : out;
      final OutputStream encryptedOut = encryptedDataGenerator.open(theOut, new byte[4096]);

      final PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
          CompressionAlgorithmTags.ZIP);
      final OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte[4096]);

      PGPSecretKey pgpSec = BCPGPUtils.readSecretKey(privateKeyFile);
      PGPPrivateKey signingKey = encrypt.getPrivateKey();

      PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(
          encrypt.getSecretKey().getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256));
      signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingKey);
      LOGGER.info("<-----Compressing the encrypted data----->");

      final Iterator<?> it = pgpSec.getPublicKey().getUserIDs();
      if (it.hasNext()) {
        final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        spGen.setSignerUserID(false, (String) it.next());
        signatureGenerator.setHashedSubpackets(spGen.generate());
      }
      LOGGER.info("<-----Signing the message after encryption----->");
      signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

      final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
      final OutputStream literalOut = literalDataGenerator.open(
          compressedOut,
          PGPLiteralData.BINARY,
          "filename",
          new Date(),
          new byte[4096]
      );
      final InputStream in = new ByteArrayInputStream(message);
      final byte[] buf = new byte[4096];
      for (int len; (len = in.read(buf)) > 0; ) {
        literalOut.write(buf, 0, len);
        signatureGenerator.update(buf, 0, len);

      }
      in.close();
      literalDataGenerator.close();
      signatureGenerator.generate().encode(compressedOut);
      compressedDataGenerator.close();
      encryptedDataGenerator.close();
      theOut.close();
      LOGGER.info("<-----Generated Encrypted and Signed Message successfully----->");
      return out.toByteArray();
    } catch (Exception ex) {
      throw new PGPException("Error in encrypt and sign", ex);
    }
  }

}
