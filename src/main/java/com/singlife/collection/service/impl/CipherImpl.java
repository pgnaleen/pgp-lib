package com.singlife.collection.service.impl;

import com.google.common.io.CharStreams;
import com.singlife.collection.util.BCPGPEncryptor;
import com.singlife.collection.util.Encrypt;
import com.singlife.collection.util.Signature;
import com.singlife.collection.service.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;
import java.util.Iterator;

import static org.bouncycastle.openpgp.PGPUtil.getDecoderStream;

@Service
public class CipherImpl implements Cipher {

    private static final Logger LOGGER = LoggerFactory.getLogger(CipherImpl.class);

    private String pubKey;
    private String priKey;

    @Value("${collection.key.pwd}")
    private String pwd;

    @Override
    public String decryptData(final String encryptedData) throws IOException, PGPException {
        return decrypt(new ByteArrayInputStream(encryptedData.getBytes()));
    }

    @Value("${collection.key.pub}")
    private void setPubKey(String pubKey) {
        this.pubKey = new String(Base64.getDecoder().decode(pubKey));
    }

    @Value("${sl.key.pri}")
    private void setPriKey(String priKey) {
        this.priKey = new String(Base64.getDecoder().decode(priKey));
    }

    private String decrypt(
            final InputStream in
    ) throws IOException, PGPException, IllegalArgumentException {
        Security.addProvider(new BouncyCastleProvider());

        final InputStream ins = getDecoderStream(in);

        final PGPObjectFactory pgpF = new PGPObjectFactory(ins, new BcKeyFingerprintCalculator());
        final PGPEncryptedDataList enc;

        final Object pgpFObj = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (pgpFObj instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) pgpFObj;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        if (enc == null) {
            throw new IllegalArgumentException("The message is not valid");
        }

        //
        // find the secret key
        //
        final Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            sKey = findSecretKey(pbe.getKeyID());
        }

        if (sKey == null) {
            throw new IllegalArgumentException("Secret key for message not found.");
        }

        final InputStream clear = pbe.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(sKey)
        );

        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());
        Object message = plainFact.nextObject();

        while (message != null) {
            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(
                        cData.getDataStream(),
                        new BcKeyFingerprintCalculator()
                );

                message = plainFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;

                InputStream unc = ld.getInputStream();
                String result = null;
                try (Reader reader = new InputStreamReader(unc)) {
                    result = CharStreams.toString(reader);
                }

                return result;
            }

            message = plainFact.nextObject();
        }

        throw new PGPException("Message is not a simple encrypted file - type unknown.");
    }

    private PGPPrivateKey findSecretKey(final long keyID) throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                getDecoderStream(
                        new ByteArrayInputStream(priKey.getBytes())
                ),
                new BcKeyFingerprintCalculator()
        );

        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(pwd.toCharArray())
        );
    }

    @Override
    public String encryptData(
            final String data
    ) throws IOException, PGPException, IllegalArgumentException, NoSuchProviderException {
        return encrypt(data);
    }

    private String encrypt(String data) throws PGPException, IOException, NoSuchProviderException {
        Encrypt encrypt = new Encrypt();
        encrypt.setArmored(true);
        encrypt.setCheckIntegrity(true);
        encrypt.setPublicKeyFilePath(pubKey);
        encrypt.setSigning(true);
        encrypt.setPrivateKeyFilePath(priKey);
        encrypt.setPrivateKeyPassword(pwd.toCharArray());
        BCPGPEncryptor bcpgpEncryptor = new BCPGPEncryptor(encrypt);

        return bcpgpEncryptor.encryptMessage(data);

    }

    @Override
    public String signatureGenerate(String queryParams)
            throws Exception {
        Encrypt encrypt = new Encrypt();
        encrypt.setArmored(true);
        encrypt.setCheckIntegrity(true);
        encrypt.setPublicKeyFilePath(pubKey);
        encrypt.setSigning(true);
        encrypt.setPrivateKeyFilePath(priKey);
        encrypt.setPrivateKeyPassword(pwd.toCharArray());

        Signature signature = new Signature(encrypt);
        return signature.signatureGenerate(queryParams, priKey);

    }

}
