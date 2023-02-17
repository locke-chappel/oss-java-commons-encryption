package io.github.lc.oss.commons.encryption.ephemeral;

import java.nio.charset.StandardCharsets;

import io.github.lc.oss.commons.encryption.Ciphers;

public interface EphemeralCipher {
    String encrypt(byte[] data, Ciphers cipher);

    default String encrypt(String data, Ciphers cipher) {
        return this.encrypt(data.getBytes(StandardCharsets.UTF_8), cipher);
    }

    byte[] decrypt(String data, Ciphers cipher);

    String decryptString(String data, Ciphers cipher);
}
