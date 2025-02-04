package io.github.lc.oss.commons.encryption;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.lc.oss.commons.encoding.Encodings;

public abstract class AbstractAES implements Cipher {
    private static final String DELIMITER = "$";
    private static final String DELIMITER_REGEX = "\\$";
    private static final String KEYSEC = "AES";
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    private static final int DEFAULT_SALT_BYTES = 16;

    private static SecureRandom rng = new SecureRandom();

    protected abstract int getKeySize();

    protected String getAlgorithm() {
        return "AES/GCM/NoPadding";
    }

    protected String getPasswordHash() {
        return "PBKDF2WithHmacSHA512";
    }

    protected int getPasswordIterations() {
        return 101113;
    }

    @Override
    public String encrypt(String data, char[] password) {
        return this.encrypt(data.getBytes(StandardCharsets.UTF_8), password,
                this.random(AbstractAES.DEFAULT_SALT_BYTES));
    }

    @Override
    public String encrypt(String data, char[] password, String salt) {
        return this.encrypt(data.getBytes(StandardCharsets.UTF_8), password, salt.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String encrypt(byte[] data, char[] password) {
        return this.encrypt(data, password, this.random(AbstractAES.DEFAULT_SALT_BYTES));
    }

    @Override
    public String encrypt(byte[] data, char[] password, byte[] salt) {
        byte[] iv = this.generateIV();
        byte[] cipher = this.cipher(true, data, this.getKey(password, salt), iv);
        return Encodings.Base64.encode(iv) + AbstractAES.DELIMITER + Encodings.Base64.encode(salt)
                + AbstractAES.DELIMITER + Encodings.Base64.encode(cipher);
    }

    @Override
    public byte[] encrypt(byte[] data, char[] password, byte[] salt, byte[] iv) {
        return this.cipher(true, data, this.getKey(password, salt), iv);
    }

    @Override
    public String decryptString(String data, char[] password) {
        return new String(this.decrypt(data, password), StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decrypt(String data, char[] password) {
        String[] parts = data.split(DELIMITER_REGEX);

        return this.cipher(false, Encodings.Base64.decode(parts[2]),
                this.getKey(password, Encodings.Base64.decode(parts[1])), Encodings.Base64.decode(parts[0]));
    }

    @Override
    public byte[] decrypt(byte[] data, char[] password, byte[] salt, byte[] iv) {
        return this.cipher(false, data, this.getKey(password, salt), iv);
    }

    protected byte[] cipher(boolean encrypt, byte[] data, SecretKey key, byte[] iv) {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(this.getAlgorithm());

            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), AbstractAES.KEYSEC);

            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AbstractAES.TAG_LENGTH * 8, iv);

            int mode = encrypt ? javax.crypto.Cipher.ENCRYPT_MODE : javax.crypto.Cipher.DECRYPT_MODE;
            cipher.init(mode, keySpec, gcmParameterSpec);

            return cipher.doFinal(data);
        } catch (GeneralSecurityException ex) {
            throw new RuntimeException(ex);
        }
    }

    protected byte[] generateIV() {
        return this.random(AbstractAES.IV_LENGTH);
    }

    protected byte[] random(int count) {
        byte[] bytes = new byte[count];
        AbstractAES.rng.nextBytes(bytes);
        return bytes;
    }

    protected SecretKey getKey(char[] password, byte[] salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(this.getPasswordHash());
            KeySpec spec = new PBEKeySpec(password, salt, this.getPasswordIterations(), this.getKeySize());
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (InvalidKeySpecException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }
}
