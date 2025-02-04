package io.github.lc.oss.commons.encryption.ephemeral;

import java.security.SecureRandom;
import java.util.Arrays;

import io.github.lc.oss.commons.encoding.Encodings;

public class MemoryBackedCipher extends AbstractEphemeralCipher {
    private char[] key;

    /**
     * Creates an instance using a random 4096-bit key.
     */
    public MemoryBackedCipher() {
        this(4096);
    }

    /**
     * @param keyBits The key size in bits, must be a positive multiple of 8
     */
    public MemoryBackedCipher(int keyBits) {
        if (keyBits < 8 || keyBits % 8 != 0) {
            throw new RuntimeException("Key size must be a positive multiple of 8");
        }

        byte[] data = new byte[keyBits / 8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(data);

        this.key = Encodings.Base64.encode(data).toCharArray();
    }

    /**
     * WARNING: This method will generate a new encryption key rendering all data
     * previously encrypted inaccessible.
     */
    public synchronized void rotateKey() {
        byte[] data = new byte[this.key.length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(data);

        Arrays.fill(this.key, '0');
        this.key = Encodings.Base64.encode(data).toCharArray();
    }

    @Override
    protected char[] getKey() {
        return this.key;
    }
}
