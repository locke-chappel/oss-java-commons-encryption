package io.github.lc.oss.commons.encryption;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.github.lc.oss.commons.testing.AbstractTest;

public class AES256Test extends AbstractTest {
    @Test
    public void test_strings() {
        AES256 aes = new AES256();
        String cipher = aes.encrypt("Test", "pw".toCharArray(), "salt");
        Assertions.assertNotEquals("Test", cipher);
        String clear = aes.decryptString(cipher, "pw".toCharArray());
        Assertions.assertEquals("Test", clear);
    }

    @Test
    public void test_strings_defaultSalt() {
        AES256 aes = new AES256();
        String cipher = aes.encrypt("Test", "pw".toCharArray());
        Assertions.assertNotEquals("Test", cipher);
        String clear = aes.decryptString(cipher, "pw".toCharArray());
        Assertions.assertEquals("Test", clear);
    }

    @Test
    public void test_strings_defaultSalt_v2() {
        AES256 aes = new AES256();
        String cipher = aes.encrypt("Test".getBytes(StandardCharsets.UTF_8), "pw".toCharArray());
        Assertions.assertNotEquals("Test", cipher);
        String clear = aes.decryptString(cipher, "pw".toCharArray());
        Assertions.assertEquals("Test", clear);
    }

    @Test
    public void test_encrypt() {
        AES256 aes = new AES256();
        final byte[] data = new byte[] { (byte) 0xF0 };
        final char[] password = "password".toCharArray();
        final byte[] salt = new byte[] { (byte) 0x00 };
        final byte[] iv = aes.generateIV();

        byte[] cipher = aes.encrypt(data, password, salt, iv);
        Assertions.assertNotEquals(data, cipher);

        byte[] clear = aes.decrypt(cipher, password, salt, iv);
        Assertions.assertArrayEquals(data, clear);
    }
}
