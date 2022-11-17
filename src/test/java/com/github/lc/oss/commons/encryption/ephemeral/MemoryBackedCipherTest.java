package com.github.lc.oss.commons.encryption.ephemeral;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lc.oss.commons.encryption.Ciphers;

public class MemoryBackedCipherTest {
    @Test
    public void test_badKeySize() {
        Arrays.asList(-1, 0, 1, 7, 9, 15).forEach(i -> {
            try {
                new MemoryBackedCipher(i);
                Assertions.fail("Expected exception");
            } catch (RuntimeException ex) {
                Assertions.assertEquals("KeySize must be a positive multiple of 8", ex.getMessage());
            }
        });
    }

    @Test
    public void test_intance() {
        MemoryBackedCipher cipher1 = new MemoryBackedCipher(8);
        MemoryBackedCipher cipher2 = new MemoryBackedCipher(8);

        final String src = "test";

        String encrypted = cipher1.encrypt(src, Ciphers.AES128);
        Assertions.assertNotEquals(src, encrypted);

        byte[] decrypted = cipher1.decrypt(encrypted, Ciphers.AES128);
        String decryptedString = cipher1.decryptString(encrypted, Ciphers.AES128);
        Assertions.assertEquals(src, new String(decrypted, StandardCharsets.UTF_8));
        Assertions.assertNotSame(src, decryptedString);
        Assertions.assertEquals(src, decryptedString);

        try {
            cipher2.decrypt(encrypted, Ciphers.AES128);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("javax.crypto.AEADBadTagException: Tag mismatch!", ex.getMessage());
        }
    }
}
