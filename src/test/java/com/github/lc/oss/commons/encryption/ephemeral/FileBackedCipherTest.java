package com.github.lc.oss.commons.encryption.ephemeral;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.github.lc.oss.commons.encryption.Ciphers;
import com.github.lc.oss.commons.util.IoTools;

public class FileBackedCipherTest {
    private static String tempDir = null;

    private String getTempDir() {
        if (FileBackedCipherTest.tempDir == null) {
            FileBackedCipherTest.tempDir = System.getProperty("java.io.tmpdir").replace("\\", "/");
            Assertions.assertTrue(Files.isDirectory(Paths.get(FileBackedCipherTest.tempDir)));
            if (!FileBackedCipherTest.tempDir.endsWith("/")) {
                FileBackedCipherTest.tempDir += "/";
            }
        }
        return FileBackedCipherTest.tempDir;
    }

    private String getTempFile() {
        return this.getTempDir() + "file-backed-cipher.dat";
    }

    @AfterEach
    public void cleanup() {
        File f = new File(this.getTempFile());
        f.delete();
    }

    @Test
    public void test_badPath() {
        try {
            new FileBackedCipher(null);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("KeyPath is required.", ex.getMessage());
        }

        try {
            new FileBackedCipher("");
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("KeyPath is required.", ex.getMessage());
        }

        try {
            new FileBackedCipher(" ");
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("KeyPath is required.", ex.getMessage());
        }

        try {
            new FileBackedCipher(" \t \r \n \t ");
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("KeyPath is required.", ex.getMessage());
        }
    }

    @Test
    public void test_readError() {
        try {
            new FileBackedCipher("/this/junk/better/not/exist/anywhere/on/a/real/file/system!");
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("KeyPath does not point to a valid key file. File must contain at least 1 byte", ex.getMessage());
        }
    }

    @Test
    public void test_zeroByteFile() {
        IoTools.writeToFile(new byte[0], this.getTempFile());

        try {
            new FileBackedCipher(this.getTempFile());
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("KeyPath does not point to a valid key file. File must contain at least 1 byte", ex.getMessage());
        }
    }

    @Test
    public void test_binaryFileKey() {
        IoTools.writeToFile(new byte[] { 0x00 }, this.getTempFile());
        FileBackedCipher cipher = new FileBackedCipher(this.getTempFile());

        final String src = "test";

        String encrypted = cipher.encrypt(src, Ciphers.AES128);
        Assertions.assertNotEquals(src, encrypted);

        byte[] decrypted = cipher.decrypt(encrypted, Ciphers.AES128);
        String decryptedString = cipher.decryptString(encrypted, Ciphers.AES128);
        Assertions.assertEquals(src, new String(decrypted, StandardCharsets.UTF_8));
        Assertions.assertNotSame(src, decryptedString);
        Assertions.assertEquals(src, decryptedString);
    }

    @Test
    public void test_textFileKey() {
        IoTools.writeToFile("a".getBytes(StandardCharsets.UTF_8), this.getTempFile());
        FileBackedCipher cipher = new FileBackedCipher(this.getTempFile());

        final String src = "test";

        String encrypted = cipher.encrypt(src, Ciphers.AES128);
        Assertions.assertNotEquals(src, encrypted);

        byte[] decrypted = cipher.decrypt(encrypted, Ciphers.AES128);
        String decryptedString = cipher.decryptString(encrypted, Ciphers.AES128);
        Assertions.assertEquals(src, new String(decrypted, StandardCharsets.UTF_8));
        Assertions.assertNotSame(src, decryptedString);
        Assertions.assertEquals(src, decryptedString);
    }
}
