package io.github.lc.oss.commons.encryption.ephemeral;

import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import io.github.lc.oss.commons.encryption.Ciphers;
import io.github.lc.oss.commons.testing.AbstractTest;

public class RotatingMemoryBackedCipherTest extends AbstractTest {
    private class ThreadHelper implements Runnable {
        private BlockingQueue<Object> lock = new ArrayBlockingQueue<>(1);
        private RotatingMemoryBackedCipher rmbc;
        private boolean complete = false;
        private Object key;
        private int expectedKeyIndex;

        public ThreadHelper(RotatingMemoryBackedCipher rmbc, int expectedKeyIndex) {
            this.rmbc = rmbc;
            this.expectedKeyIndex = expectedKeyIndex;
        }

        public void go() {
            this.lock.add(this);
        }

        public boolean isComplete() {
            return this.complete;
        }

        public Object key() {
            return this.key;
        }

        @Override
        public void run() {
            try {
                this.lock.take();

                this.rmbc.encrypt("data");
                this.key = ((Object[]) RotatingMemoryBackedCipherTest.this.getField("keys",
                        rmbc))[this.expectedKeyIndex];
            } catch (InterruptedException ex) {
                Assertions.fail("Unexpected exception");
            } finally {
                this.complete = true;
            }
        }
    }

    @Test
    public void test_badKeySize() {
        Arrays.asList(-1, 0, 1, 7, 9, 15).forEach(i -> {
            try {
                new RotatingMemoryBackedCipher(i, 0, 0);
                Assertions.fail("Expected exception");
            } catch (RuntimeException ex) {
                Assertions.assertEquals("Key size must be a positive multiple of 8", ex.getMessage());
            }
        });
    }

    @Test
    public void test_defaults() {
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher();

        Object[] keys = this.getField("keys", rmbc);
        Assertions.assertEquals(2, keys.length);

        int keySize = this.getField("keyBits", rmbc);
        Assertions.assertEquals(4096, keySize);

        long keyttl = this.getField("keyTtl", rmbc);
        Assertions.assertEquals(60l * 60l * 1000l, keyttl);
    }

    @Test
    public void test_keyRotation() {
        /*
         * Special Note:
         * 
         * This test is highly sensitive to encryption/decryption performance. Therefore
         * this test conducts a simple benchmark to ensure the keys live long enough to
         * operate properly but short enough to keep the test as fast as possible.
         * 
         * Why? We need to test the actual expiration of keys to prove that they rotate
         * properly but that means actually waiting for them to expire. If the test is
         * ran on slower hardware (say an ARM node without AES extensions) then we run
         * into a scenario where the encryption operations make take "too long" for the
         * key's lifetime. The benchmark helps us calculate the optimal values per
         * hardware (one size does not fit all unless you want really slow :) ).
         */

        // start benchmark
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher(512, 1, 1000);
        long start = System.currentTimeMillis();
        String cipher0 = rmbc.encrypt("Data-0", Ciphers.AES128);
        long stop = System.currentTimeMillis();
        final long encTime = stop - start;

        start = System.currentTimeMillis();
        rmbc.decryptString(cipher0, Ciphers.AES128);
        stop = System.currentTimeMillis();
        final long decTime = stop - start;

        // Configure test for current hardware
        /*
         * Note: we perform at most 2 encryption operations or 4 decryption operations
         * per rotation. So our optimal ttl is the sum of that plus a half second
         * buffer.
         */
        final int keySlots = 3;
        final long ttl = (2 * encTime) + (4 * decTime) + 500;
        final long ttlWait = ttl + 250;
        final long maxTtlWait = keySlots * ttl + 250;
        final long buffer = 100;

        // now the real test
        rmbc = new RotatingMemoryBackedCipher(512, keySlots, ttl);

        final String data1 = "Data-1";
        final String data2 = "Data-2";
        final String data3 = "Data-3";
        final String data4 = "Data-4";
        final String data5 = "Data-5";

        Object[] keys = this.getField("keys", rmbc);

        String cipher1 = rmbc.encrypt(data1, Ciphers.AES128);
        String cipher2 = rmbc.encrypt(data2, Ciphers.AES128);
        final long expires1 = this.getField("expires", keys[0]);
        this.waitUntil(() -> System.currentTimeMillis() > expires1 + buffer, ttlWait);

        String cipher3 = rmbc.encrypt(data3, Ciphers.AES128);
        final long expires2 = this.getField("expires", keys[1]);
        this.waitUntil(() -> System.currentTimeMillis() > expires2 + buffer, ttlWait);

        String cipher4 = rmbc.encrypt(data4, Ciphers.AES128);

        Assertions.assertEquals(data1, rmbc.decryptString(cipher1, Ciphers.AES128));
        Assertions.assertEquals(data2, rmbc.decryptString(cipher2, Ciphers.AES128));
        Assertions.assertEquals(data3, rmbc.decryptString(cipher3, Ciphers.AES128));
        Assertions.assertEquals(data4, rmbc.decryptString(cipher4, Ciphers.AES128));

        final long expires3 = this.getField("expires", keys[2]);
        this.waitUntil(() -> System.currentTimeMillis() > expires3 + buffer, ttlWait);

        String cipher5 = rmbc.encrypt(data5, Ciphers.AES128);

        Assertions.assertEquals(data3, rmbc.decryptString(cipher3, Ciphers.AES128));
        Assertions.assertEquals(data4, rmbc.decryptString(cipher4, Ciphers.AES128));
        Assertions.assertEquals(data5, rmbc.decryptString(cipher5, Ciphers.AES128));

        final long expires4 = this.getField("expires", keys[0]);
        this.waitUntil(() -> System.currentTimeMillis() > expires4 + buffer, ttlWait);

        // Key has been rotated out (no matching hashcode)
        try {
            rmbc.decryptString(cipher1, Ciphers.AES128);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            // pass
        }

        try {
            rmbc.decryptString(cipher2, Ciphers.AES128);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            // pass
        }

        // Cause next key to expire
        final long ttl5 = this.getField("maxTtl", keys[1]);
        this.waitUntil(() -> System.currentTimeMillis() > ttl5 + buffer, maxTtlWait);

        // Key exists but has reached max ttl
        try {
            rmbc.decryptString(cipher3, Ciphers.AES128);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            // pass
        }
    }

    @Test
    public void test_noKeys() {
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher();

        String cipher = rmbc.encrypt(new byte[] { 0x00 });

        // blow away the keys
        Object[] keys = this.getField("keys", rmbc);
        for (int i = 0; i < keys.length; i++) {
            keys[i] = null;
        }

        try {
            rmbc.decrypt(cipher);
            Assertions.fail("Expected exception");
        } catch (RuntimeException ex) {
            // pass
        }
    }

    @Test
    public void test_nonCipherException() {
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher();
        String cipher = rmbc.encrypt("data");

        try {
            // Pass in just the hashcode + $ causing the encrypted value to be empty
            rmbc.decrypt(cipher.substring(0, cipher.indexOf("$") + 1), Ciphers.AES256);

            Assertions.fail("Expected exception");
        } catch (Throwable ex) {
            Assertions.assertFalse(ex instanceof AssertionFailedError);
            Assertions.assertNotEquals("Unable to decrypt value using available keys.", ex.getMessage());
        }
    }

    @Test
    public void test_cipherException() {
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher();
        String cipher = rmbc.encrypt("data");

        // blow away the key but keep the record
        Object[] keys = this.getField("keys", rmbc);
        this.setField("key", null, keys[0]);

        try {
            rmbc.decrypt(cipher, Ciphers.AES256);

            Assertions.fail("Expected exception");
        } catch (Throwable ex) {
            Assertions.assertFalse(ex instanceof AssertionFailedError);
            Assertions.assertEquals("Unable to decrypt value using available keys.", ex.getMessage());
        }
    }

    @Test
    public void test_threading_nullKey() {
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher(8, 3, 10000);

        ThreadHelper h1 = new ThreadHelper(rmbc, 0);
        ThreadHelper h2 = new ThreadHelper(rmbc, 0);

        // ready...
        Thread t1 = new Thread(h1);
        Thread t2 = new Thread(h2);

        // set...
        t1.start();
        t2.start();

        // go...
        h1.go();
        h2.go();

        this.waitUntil(() -> h1.isComplete());
        this.waitUntil(() -> h2.isComplete());

        // h2 should have waited for h1 to complete and then seen the new key and not
        // created another one
        Object[] keys = this.getField("keys", rmbc);
        Object key1 = h1.key();
        Object key2 = h2.key();

        Assertions.assertSame(key1, key2);
        Assertions.assertSame(keys[0], key1);
        Assertions.assertSame(keys[0], key2);
        Assertions.assertNull(keys[1]);
        Assertions.assertNull(keys[2]);
    }

    @Test
    public void test_threading_expiredKey() {
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher(8, 3, 1000);

        ThreadHelper h1 = new ThreadHelper(rmbc, 1);
        ThreadHelper h2 = new ThreadHelper(rmbc, 1);

        // monitor keys
        Object[] keys = this.getField("keys", rmbc);

        // create first key and let it expire
        rmbc.encrypt("data");
        Object firstKey = keys[0];

        final long firstExpires = this.getField("expires", firstKey);
        this.waitUntil(() -> System.currentTimeMillis() > firstExpires + 100, 3500);

        // ready...
        Thread t1 = new Thread(h1);
        Thread t2 = new Thread(h2);

        // set...
        t1.start();
        t2.start();

        // go...
        h1.go();
        h2.go();

        this.waitUntil(() -> h1.isComplete());
        this.waitUntil(() -> h2.isComplete());

        // h2 should have waited for h1 to complete and then seen the new key and not
        // created another one
        Object key1 = h1.key();
        Object key2 = h2.key();

        Assertions.assertNotSame(firstKey, key1);
        Assertions.assertSame(key1, key2);
        Assertions.assertSame(keys[0], firstKey);
        Assertions.assertSame(keys[1], key1);
        Assertions.assertSame(keys[1], key2);
        Assertions.assertNull(keys[2]);
    }

    @Test
    public void test_threading_onlyCreateOneKey() {
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher(8, 1, 1000);

        // monitor keys
        Object[] keys = this.getField("keys", rmbc);

        ThreadHelper h1 = new ThreadHelper(rmbc, 0);
        ThreadHelper h2 = new ThreadHelper(rmbc, 0);
        ThreadHelper h3 = new ThreadHelper(rmbc, 0);
        ThreadHelper h4 = new ThreadHelper(rmbc, 0);

        // ready...
        Thread t1 = new Thread(h1);
        Thread t2 = new Thread(h2);
        Thread t3 = new Thread(h3);
        Thread t4 = new Thread(h4);

        // set...
        t1.start();
        t2.start();
        t3.start();
        t4.start();

        // go...
        h1.go();
        h2.go();
        h3.go();
        h4.go();

        this.waitUntil(() -> h1.isComplete());
        this.waitUntil(() -> h2.isComplete());
        this.waitUntil(() -> h3.isComplete());
        this.waitUntil(() -> h4.isComplete());

        // h2-4 should have waited for h1 to complete and then seen the new key and not
        // created another one
        Object key1 = h1.key();
        Object key2 = h2.key();
        Object key3 = h3.key();
        Object key4 = h4.key();

        Assertions.assertSame(key1, key2);
        Assertions.assertSame(key1, key3);
        Assertions.assertSame(key1, key4);
        Assertions.assertSame(keys[0], key1);
    }

    @Test
    public void test_threading_expiredKey_onlyCreateOneKey() {
        RotatingMemoryBackedCipher rmbc = new RotatingMemoryBackedCipher(8, 1, 1000);

        ThreadHelper h1 = new ThreadHelper(rmbc, 0);
        ThreadHelper h2 = new ThreadHelper(rmbc, 0);
        ThreadHelper h3 = new ThreadHelper(rmbc, 0);
        ThreadHelper h4 = new ThreadHelper(rmbc, 0);

        // monitor keys
        Object[] keys = this.getField("keys", rmbc);

        // create first key and let it expire
        rmbc.encrypt("data");
        Object firstKey = keys[0];

        final long firstExpires = this.getField("expires", firstKey);
        this.waitUntil(() -> System.currentTimeMillis() > firstExpires + 100, 3500);

        // ready...
        Thread t1 = new Thread(h1);
        Thread t2 = new Thread(h2);
        Thread t3 = new Thread(h3);
        Thread t4 = new Thread(h4);

        // set...
        t1.start();
        t2.start();
        t3.start();
        t4.start();

        // go...
        h1.go();
        h2.go();
        h3.go();
        h4.go();

        this.waitUntil(() -> h1.isComplete());
        this.waitUntil(() -> h2.isComplete());
        this.waitUntil(() -> h3.isComplete());
        this.waitUntil(() -> h4.isComplete());

        // h2-4 should have waited for h1 to complete and then seen the new key and not
        // created another one
        Object key1 = h1.key();
        Object key2 = h2.key();
        Object key3 = h3.key();
        Object key4 = h4.key();

        Assertions.assertNotSame(firstKey, key1);
        Assertions.assertSame(key1, key2);
        Assertions.assertSame(key1, key3);
        Assertions.assertSame(key1, key4);
        Assertions.assertSame(keys[0], key1);
    }
}
