package io.github.lc.oss.commons.encryption;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import io.github.lc.oss.commons.testing.AbstractTest;

public class AbstractAESTest extends AbstractTest {
    private static class BadPasswordHashAES extends AbstractAES {
        @Override
        protected String getPasswordHash() {
            return "junk";
        }

        @Override
        protected int getKeySize() {
            return 128;
        }
    }

    @Test
    public void test_getKey() {
        AbstractAES aes = new BadPasswordHashAES();

        try {
            aes.getKey("pw".toCharArray(), new byte[0]);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            Assertions.assertEquals("java.security.NoSuchAlgorithmException: junk SecretKeyFactory not available", ex.getMessage());
        }
    }
}
