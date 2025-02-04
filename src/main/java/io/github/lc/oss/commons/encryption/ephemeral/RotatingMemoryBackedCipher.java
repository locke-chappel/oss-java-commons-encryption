package io.github.lc.oss.commons.encryption.ephemeral;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import io.github.lc.oss.commons.encoding.Encodings;
import io.github.lc.oss.commons.encryption.Cipher;

/**
 * A memory back temporary cipher manager.<br/>
 * <br />
 * This class will allocate the specified number of key slots with a specified
 * time to live for encrypt operations. Keys will be generated on-demand during
 * the encryption operation. Encrypted values will contain the ID of which key
 * they used so that key lookups are efficient. If the matching key is found and
 * has not exceeded it's decryption TTL (e.g. encryption TTL x key slots) the
 * value is decrypted else a {@linkplain RuntimeException} is thrown.
 */
public class RotatingMemoryBackedCipher implements EphemeralCipher {
    private static final String DELIMITER = "$";

    private static class Key {
        public static Key newKey(int keyBits, long ttl, long maxTtl) {
            byte[] data = new byte[keyBits / 8];
            SecureRandom random = new SecureRandom();
            random.nextBytes(data);

            return new Key(Encodings.Base64.encode(data).toCharArray(), ttl, maxTtl);
        }

        private final long expires;
        private final long maxTtl;
        private char[] key;

        public Key(char[] key, long ttl, long maxTtl) {
            this.key = key;
            this.expires = System.currentTimeMillis() + ttl;
            this.maxTtl = System.currentTimeMillis() + maxTtl;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() >= this.expires;
        }

        public boolean isValid() {
            return System.currentTimeMillis() < this.maxTtl;
        }

        public char[] getKey() {
            return this.key;
        }
    }

    private final int keyBits;
    private final long keyTtl;
    private final long maxTtl;
    private final Key[] keys;

    private int keyIndex;

    /***
     * Creates a default instance using 4096-bit keys, 2 key slots, with an
     * encryption TTL of 1 hour (resulting encrypted values being decryptable for a
     * total of 2 hours maximum).
     */
    public RotatingMemoryBackedCipher() {
        this(4096, 2, 60l * 60l * 1000l);
    }

    /***
     * @param keyBits       Length of key in bits, must be a positive multiple of 8
     * @param keySlots      Number of key slots to allocate
     * @param encryptionTtl Time to Live of each key for encryption purposes
     *                      (decryption TTL is this value times the number of key
     *                      slots)
     */
    public RotatingMemoryBackedCipher(int keyBits, int keySlots, long encryptionTtl) {
        if (keyBits < 8 || keyBits % 8 != 0) {
            throw new RuntimeException("Key size must be a positive multiple of 8");
        }

        this.keyBits = keyBits;
        this.keyTtl = encryptionTtl;
        this.maxTtl = encryptionTtl * keySlots;

        this.keys = new Key[keySlots];
        this.keyIndex = 0;
    }

    @Override
    public String encrypt(byte[] data, Cipher cipher) {
        Key current = this.keys[this.keyIndex];
        if (current == null) {
            synchronized (this.keys) {
                current = this.keys[this.keyIndex];
                if (current == null) {
                    current = Key.newKey(this.keyBits, this.keyTtl, this.maxTtl);
                    this.keys[this.keyIndex] = current;
                }
            }
        } else if (current.isExpired()) {
            synchronized (this.keys) {
                current = this.keys[this.keyIndex];
                if (current.isExpired()) {
                    current = Key.newKey(this.keyBits, this.keyTtl, this.maxTtl);

                    int i = this.keyIndex + 1;
                    if (i >= this.keys.length) {
                        i = 0;
                    }

                    this.keys[i] = current;
                    this.keyIndex = i;
                }
            }
        }

        return this.toBase64(current.hashCode()) + DELIMITER + cipher.encrypt(data, current.getKey());
    }

    @Override
    public byte[] decrypt(String data, Cipher cipher) {
        int id = this.fromBase64(data.substring(0, data.indexOf(DELIMITER)));
        String encrypted = data.substring(data.indexOf(DELIMITER) + 1);

        int index = this.keyIndex;
        Key key = null;
        do {
            key = this.keys[index];
            if (key != null && key.hashCode() == id && key.isValid()) {
                try {
                    return cipher.decrypt(encrypted, key.getKey());
                } catch (RuntimeException ex) {
                    if (!(ex.getCause() instanceof GeneralSecurityException)) {
                        throw ex;
                    }
                }
            }

            index--;
            if (index < 0) {
                index = this.keys.length - 1;
            }
        } while (index != this.keyIndex);

        throw new RuntimeException("Unable to decrypt value using available keys.");
    }

    @Override
    public String decryptString(String data, Cipher cipher) {
        return new String(this.decrypt(data, cipher), StandardCharsets.UTF_8);
    }

    private String toBase64(int value) {
        byte[] bytes = new byte[] { //
                (byte) (value >> 24), //
                (byte) (value >> 16), //
                (byte) (value >> 8), //
                (byte) value//
        };
        return Encodings.Base64.encode(bytes);
    }

    private int fromBase64(String value) {
        byte[] bytes = Encodings.Base64.decode(value);
        return ((bytes[0] & 0xFF) << 24) | //
                ((bytes[1] & 0xFF) << 16) | //
                ((bytes[2] & 0xFF) << 8) | //
                ((bytes[3] & 0xFF) << 0);
    }
}
