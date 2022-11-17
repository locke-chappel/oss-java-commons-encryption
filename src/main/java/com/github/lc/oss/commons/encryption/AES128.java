package com.github.lc.oss.commons.encryption;

class AES128 extends AbstractAES {
    @Override
    protected int getKeySize() {
        return 128;
    }
}
