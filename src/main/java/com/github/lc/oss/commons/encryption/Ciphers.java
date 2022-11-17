package com.github.lc.oss.commons.encryption;

import java.util.Set;

import com.github.lc.oss.commons.util.TypedEnumCache;

public enum Ciphers implements Cipher {
    AES128(new AES128()),
    AES256(new AES256());

    private static final TypedEnumCache<Ciphers, Ciphers> CACHE = new TypedEnumCache<>(Ciphers.class, false);

    public static final Set<Ciphers> all() {
        return Ciphers.CACHE.values();
    }

    public static Ciphers byName(String name) {
        return Ciphers.CACHE.byName(name);
    }

    public static boolean hasName(String name) {
        return Ciphers.CACHE.hasName(name);
    }

    public static Ciphers tryParse(String name) {
        return Ciphers.CACHE.tryParse(name);
    }

    private final Cipher cipher;

    private Ciphers(Cipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public String encrypt(String data, char[] password) {
        return this.cipher.encrypt(data, password);
    }

    @Override
    public String encrypt(String data, char[] password, String salt) {
        return this.cipher.encrypt(data, password, salt);
    }

    @Override
    public String encrypt(byte[] data, char[] password) {
        return this.cipher.encrypt(data, password);
    }

    @Override
    public String encrypt(byte[] data, char[] password, byte[] salt) {
        return this.cipher.encrypt(data, password, salt);
    }

    @Override
    public byte[] encrypt(byte[] data, char[] password, byte[] salt, byte[] iv) {
        return this.cipher.encrypt(data, password, salt, iv);
    }

    @Override
    public String decryptString(String data, char[] password) {
        return this.cipher.decryptString(data, password);
    }

    @Override
    public byte[] decrypt(String data, char[] password) {
        return this.cipher.decrypt(data, password);
    }

    @Override
    public byte[] decrypt(byte[] data, char[] password, byte[] salt, byte[] iv) {
        return this.cipher.decrypt(data, password, salt, iv);
    }
}
