package com.singlife.collection.service;

import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;
import java.security.NoSuchProviderException;

public interface EncryptionService {

    String encrypt(String requestDto) throws PGPException, IOException, NoSuchProviderException;

    void encryptFile(String file) throws PGPException, IOException, NoSuchProviderException;

    String decrypt(String requestDto) throws PGPException, IOException, NoSuchProviderException;

    void decryptFile(String encryptedString) throws PGPException, IOException, NoSuchProviderException;

    String signatureGenerate(String queryParams) throws Exception;
}
