package io.github.lc.oss.commons.encryption.ephemeral;

import io.github.lc.oss.commons.encryption.Cipher;

public abstract class AbstractEphemeralCipher implements EphemeralCipher {
    protected abstract char[] getKey();

    @Override
    public String encrypt(byte[] data, Cipher cipher) {
        return cipher.encrypt(data, this.getKey());
    }

    @Override
    public byte[] decrypt(String data, Cipher cipher) {
        return cipher.decrypt(data, this.getKey());
    }

    @Override
    public String decryptString(String data, Cipher cipher) {
        return cipher.decryptString(data, this.getKey());
    }
}
