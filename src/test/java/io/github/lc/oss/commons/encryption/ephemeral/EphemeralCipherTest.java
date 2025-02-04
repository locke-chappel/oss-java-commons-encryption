package io.github.lc.oss.commons.encryption.ephemeral;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.github.lc.oss.commons.encryption.Cipher;
import io.github.lc.oss.commons.encryption.Ciphers;
import io.github.lc.oss.commons.testing.AbstractTest;

public class EphemeralCipherTest extends AbstractTest {
    @Test
    public void test_defaultIsAES256() {
        EphemeralCipher ec = new EphemeralCipher() {

            @Override
            public String encrypt(byte[] data, Cipher cipher) {
                Assertions.assertSame(Ciphers.AES256, cipher);
                return null;
            }

            @Override
            public String decryptString(String data, Cipher cipher) {
                Assertions.assertSame(Ciphers.AES256, cipher);
                return null;
            }

            @Override
            public byte[] decrypt(String data, Cipher cipher) {
                Assertions.assertSame(Ciphers.AES256, cipher);
                return null;
            }
        };

        ec.encrypt(new byte[] { 0x00 });
        ec.encrypt("");

        ec.decrypt("");
        ec.decryptString("");
    }
}
