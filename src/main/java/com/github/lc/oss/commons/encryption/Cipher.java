package com.github.lc.oss.commons.encryption;

interface Cipher {
    String encrypt(String data, char[] password);

    String encrypt(String data, char[] password, String salt);

    String encrypt(byte[] data, char[] password);

    String encrypt(byte[] data, char[] password, byte[] salt);

    byte[] encrypt(byte[] data, char[] password, byte[] salt, byte[] iv);

    String decryptString(String data, char[] password);

    byte[] decrypt(String data, char[] password);

    byte[] decrypt(byte[] data, char[] password, byte[] salt, byte[] iv);
}
