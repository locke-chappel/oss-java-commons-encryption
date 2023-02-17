package io.github.lc.oss.commons.encryption.ephemeral;

import io.github.lc.oss.commons.encoding.Encodings;
import io.github.lc.oss.commons.util.IoTools;

public class FileBackedCipher extends AbstractEphemeralCipher {
    private final char[] key;

    public FileBackedCipher(String keyPath) {
        if (keyPath == null || keyPath.trim().equals("")) {
            throw new RuntimeException("KeyPath is required.");
        }

        byte[] data = IoTools.readFile(keyPath);
        if (data == null || data.length < 1) {
            throw new RuntimeException("KeyPath does not point to a valid key file. File must contain at least 1 byte");
        }
        this.key = Encodings.Base64.encode(data).toCharArray();
    }

    @Override
    protected char[] getKey() {
        return this.key;
    }
}
