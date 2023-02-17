package io.github.lc.oss.commons.encryption;

class AES256 extends AbstractAES {
    @Override
    protected int getKeySize() {
        return 256;
    }
}
