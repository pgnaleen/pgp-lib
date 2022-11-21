package com.pgp.util;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class BCPGPUtils {

  public static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
    InputStream keyIn = new ByteArrayInputStream(fileName.getBytes());
    PGPPublicKey pubKey = readPublicKey(keyIn);
    keyIn.close();
    return pubKey;
  }

  public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
    PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
        PGPUtil.getDecoderStream(in),
        new JcaKeyFingerprintCalculator()
    );
    Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
    while (keyRingIter.hasNext()) {
      PGPPublicKeyRing keyRing = keyRingIter.next();
      Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
      while (keyIter.hasNext()) {
        PGPPublicKey key = keyIter.next();
        if (key.isEncryptionKey()) {
          return key;
        }
      }
    }

    throw new IllegalArgumentException("Can't find encryption key in key ring.");
  }

  public static PGPSecretKey readSecretKey(String fileName) throws IOException, PGPException {
    InputStream keyIn = new BufferedInputStream(new ByteArrayInputStream(fileName.getBytes(
        StandardCharsets.UTF_8)));
    PGPSecretKey secKey = readSecretKey(keyIn);
    keyIn.close();
    return secKey;
  }

  public static PGPSecretKey readSecretKey(InputStream in) throws IOException, PGPException {
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(in),
        new JcaKeyFingerprintCalculator()
    );
    Iterator<PGPSecretKeyRing> keyRingIter = pgpSec.getKeyRings();
    while (keyRingIter.hasNext()) {
      PGPSecretKeyRing keyRing = keyRingIter.next();
      Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
      while (keyIter.hasNext()) {
        PGPSecretKey key = keyIter.next();
        if (key.isSigningKey()) {
          return key;
        }
      }
    }
    throw new IllegalArgumentException("Can't find signing key in key ring.");
  }

}
