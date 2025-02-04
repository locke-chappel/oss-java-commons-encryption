package io.github.lc.oss.commons.encryption.ephemeral;

import java.nio.charset.StandardCharsets;

import io.github.lc.oss.commons.encryption.Ciphers;

public interface EphemeralCipher {
    default String encrypt(byte[] data) {
        return this.encrypt(data, Ciphers.AES256);
    }

    String encrypt(byte[] data, Ciphers cipher);

    default String encrypt(String data) {
        return this.encrypt(data, Ciphers.AES256);
    }

    default String encrypt(String data, Ciphers cipher) {
        return this.encrypt(data.getBytes(StandardCharsets.UTF_8), cipher);
    }

    default byte[] decrypt(String data) {
        return this.decrypt(data, Ciphers.AES256);
    }

    byte[] decrypt(String data, Ciphers cipher);

    default String decryptString(String data) {
        return this.decryptString(data, Ciphers.AES256);
    }

    String decryptString(String data, Ciphers cipher);
}
