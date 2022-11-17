package com.github.lc.oss.commons.encryption;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lc.oss.commons.testing.AbstractTest;

public class CiphersTest extends AbstractTest {
    @Test
    public void test_caching() {
        Set<Ciphers> expected = new HashSet<>(Arrays.asList(Ciphers.values()));
        Set<Ciphers> actual = Ciphers.all();

        Assertions.assertNotSame(expected, actual);
        Assertions.assertEquals(expected, actual);
        Assertions.assertTrue(expected.containsAll(actual));
        Assertions.assertTrue(actual.containsAll(expected));

        Assertions.assertTrue(Ciphers.hasName("AES256"));
        Assertions.assertTrue(Ciphers.hasName("aEs128"));

        Assertions.assertSame(Ciphers.AES128, Ciphers.byName("AES128"));
        Assertions.assertSame(Ciphers.AES256, Ciphers.byName("aEs256"));

        Assertions.assertSame(Ciphers.AES128, Ciphers.tryParse("AES128"));
        Assertions.assertSame(Ciphers.AES256, Ciphers.tryParse("aEs256"));
    }

    @Test
    public void test_notSame() {
        String cipher1a = Ciphers.AES128.encrypt("Test", "pw".toCharArray(), "salt");
        String cipher1b = Ciphers.AES128.encrypt("Test", "pw".toCharArray(), "salt");
        String cipher2a = Ciphers.AES256.encrypt("Test", "pw".toCharArray(), "salt");
        String cipher2b = Ciphers.AES256.encrypt("Test", "pw".toCharArray(), "salt");
        Assertions.assertNotEquals(cipher1a, cipher1b);
        Assertions.assertNotEquals(cipher2a, cipher2b);
        Assertions.assertNotEquals(cipher1a, cipher2a);
        Assertions.assertNotEquals(cipher1a, cipher2b);
        Assertions.assertNotEquals(cipher1b, cipher2a);
        Assertions.assertNotEquals(cipher1b, cipher2b);
        Assertions.assertEquals(cipher1a.length(), cipher1b.length());
        Assertions.assertEquals(cipher2a.length(), cipher2b.length());

        try {
            Ciphers.AES256.decrypt(cipher1a, "pw".toCharArray());
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertTrue(ex.getMessage().contains("javax.crypto.AEADBadTagException"));
        }
    }

    @Test
    public void test_methods() {
        final String data = "data";
        final char[] password = "password".toCharArray();
        final String saltStr = "salt";
        final byte[] salt = saltStr.getBytes(StandardCharsets.UTF_8);
        final byte[] iv = new AES128().generateIV();

        for (Cipher c : Ciphers.all()) {
            String cipher1 = c.encrypt(data.getBytes(StandardCharsets.UTF_8), password, salt);
            byte[] cipher2 = c.encrypt(data.getBytes(StandardCharsets.UTF_8), password, salt, iv);
            String cipher3 = c.encrypt(data, password, saltStr);
            String cipher4 = c.encrypt(data, password);
            String cipher5 = c.encrypt(data.getBytes(StandardCharsets.UTF_8), password);

            String clear1 = c.decryptString(cipher1, password);
            byte[] clear2 = c.decrypt(cipher2, password, salt, iv);
            byte[] clear3 = c.decrypt(cipher3, password);
            String clear4 = c.decryptString(cipher4, password);
            String clear5 = c.decryptString(cipher5, password);
            Assertions.assertEquals(data, clear1);
            Assertions.assertArrayEquals(data.getBytes(StandardCharsets.UTF_8), clear2);
            Assertions.assertArrayEquals(data.getBytes(StandardCharsets.UTF_8), clear3);
            Assertions.assertEquals(data, clear4);
            Assertions.assertEquals(data, clear5);
        }
    }
}
