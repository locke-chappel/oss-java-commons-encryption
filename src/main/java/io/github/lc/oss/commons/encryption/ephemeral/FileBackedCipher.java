package io.github.lc.oss.commons.encryption.ephemeral;

import io.github.lc.oss.commons.encoding.Encodings;
import io.github.lc.oss.commons.util.IoTools;

public class FileBackedCipher extends AbstractEphemeralCipher {
    private final char[] key;

    /***
     * @param keyPath The path to the key file. WARNING: This path should not be
     *                exposed to user input. It is intended to be used as a
     *                deployment configured value.
     */
    public FileBackedCipher(String keyPath) {
        if (keyPath == null || keyPath.trim().equals("")) {
            throw new RuntimeException("Key path is required.");
        }

        byte[] data = IoTools.readFile(keyPath);
        if (data == null || data.length < 1) {
            throw new RuntimeException(
                    "Key path does not point to a valid key file. File must contain at least 1 byte.");
        }
        this.key = Encodings.Base64.encode(data).toCharArray();
    }

    @Override
    protected char[] getKey() {
        return this.key;
    }
}
