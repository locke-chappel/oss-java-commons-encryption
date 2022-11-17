package com.github.lc.oss.commons.encryption.ephemeral;

import java.security.SecureRandom;

import com.github.lc.oss.commons.encoding.Encodings;

public class MemoryBackedCipher extends AbstractEphemeralCipher {
    private final char[] key;

    public MemoryBackedCipher(int keyBits) {
        if (keyBits < 8 || keyBits % 8 != 0) {
            throw new RuntimeException("KeySize must be a positive multiple of 8");
        }
        byte[] data = new byte[keyBits / 8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(data);
        this.key = Encodings.Base64.encode(data).toCharArray();
    }

    @Override
    protected char[] getKey() {
        return this.key;
    }
}
