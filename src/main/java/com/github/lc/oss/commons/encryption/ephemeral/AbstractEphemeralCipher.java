package com.github.lc.oss.commons.encryption.ephemeral;

import com.github.lc.oss.commons.encryption.Ciphers;

public abstract class AbstractEphemeralCipher implements EphemeralCipher {
    protected abstract char[] getKey();

    @Override
    public String encrypt(byte[] data, Ciphers cipher) {
        return cipher.encrypt(data, this.getKey());
    }

    @Override
    public byte[] decrypt(String data, Ciphers cipher) {
        return cipher.decrypt(data, this.getKey());
    }

    @Override
    public String decryptString(String data, Ciphers cipher) {
        return cipher.decryptString(data, this.getKey());
    }
}
