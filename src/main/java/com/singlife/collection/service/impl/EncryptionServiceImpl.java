package com.singlife.collection.service.impl;

import com.singlife.collection.service.Cipher;
import com.singlife.collection.service.EncryptionService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Optional;

@Service
public class EncryptionServiceImpl implements EncryptionService {

    @Value("${pay-now.key.pwd}")
    private String passPhase;

    private final Cipher cipher;

    public EncryptionServiceImpl(Cipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public void encryptFile(String file) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            PGPFileEncryptionServiceImpl.encryptFile("output_encrypted_file.asc",
                    "src/main/resources/Capture.PNG",
                    "src/main/resources/0xD89B5951-pub.asc", true, false);
        } catch (IOException | NoSuchProviderException | PGPException e) {
            throw new RuntimeException("File encryption error");
        }
    }

    @Override
    public void decryptFile(String encryptedFile) {
        Security.addProvider(new BouncyCastleProvider());

//        InputStream targetStream = new ByteArrayInputStream(encryptionInfo.getEncryptedFile().getBytes());

        try {
            PGPFileEncryptionServiceImpl.decryptFile("output_encrypted_file.asc",
                    "src/main/resources/0xD89B5951-sec.asc",
                    passPhase.toCharArray(),
                    new File("no_need_name_as_encrypted_file_has_name").getName());
        } catch (IOException | NoSuchProviderException e) {
            throw new RuntimeException("File decryption error");
        }
    }

    @Override
    public String encrypt(String requestDto) {
        Optional<String> requestBody = Optional.of(requestDto);
        try {
            return cipher.encryptData(requestBody.get());
        } catch (IOException | PGPException | NoSuchProviderException e) {
            throw new RuntimeException("File encryption error");
        }
    }

    @Override
    public String decrypt(String requestDto) {
        Optional<String> requestBody = Optional.of(requestDto);
        try {
            return cipher.decryptData(requestBody.get());
        } catch (IOException | PGPException e) {
            throw new RuntimeException("File decryption error");
        }
    }

    @Override
    public String signatureGenerate(String queryParams) {
        Optional<String> queryParam = Optional.of(queryParams);
        try {
            return cipher.signatureGenerate(queryParam.get());
        } catch (Exception e) {
            throw new RuntimeException("signature generation error");
        }
    }
}
