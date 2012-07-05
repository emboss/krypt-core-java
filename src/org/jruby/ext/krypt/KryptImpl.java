package org.jruby.ext.krypt;

import java.security.MessageDigest;

/**
 *
 * @author Vipul A M <vipulnsward@gmail.com>
 *
 * Credits jruby-ossl
 */

public class KryptImpl {
 
     /**
     * No instantiating this class...
     */
    private KryptImpl() {}
    
    public static interface KeyAndIv {
        byte[] getKey();
        byte[] getIv();
    }
    
    private static class KeyAndIvImpl implements KeyAndIv {
        private final byte[] key;
        private final byte[] iv;
        public KeyAndIvImpl(byte[] key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }
        public byte[] getKey() {
            return key;
        }
        public byte[] getIv() {
            return iv;
        }
    }
    
    public static KeyAndIv EVP_BytesToKey(int key_len, int iv_len, MessageDigest md, byte[] salt, byte[] data, int count) {
        byte[] key = new byte[key_len];
        byte[]  iv = new byte[iv_len];
        int key_ix = 0;
        int iv_ix = 0;
        byte[] md_buf = null;
        int nkey = key_len;
        int niv = iv_len;
        int i = 0;
        if(data == null) {
            return new KeyAndIvImpl(key,iv);
        }
        int addmd = 0;
        for(;;) {
            md.reset();
            if(addmd++ > 0) {
                md.update(md_buf);
            }
            md.update(data);
            if(null != salt) {
                md.update(salt,0,8);
            }
            md_buf = md.digest();
            for(i=1;i<count;i++) {
                md.reset();
                md.update(md_buf);
                md_buf = md.digest();
            }
            i=0;
            if(nkey > 0) {
                for(;;) {
                    if(nkey == 0) break;
                    if(i == md_buf.length) break;
                    key[key_ix++] = md_buf[i];
                    nkey--;
                    i++;
                }
            }
            if(niv > 0 && i != md_buf.length) {
                for(;;) {
                    if(niv == 0) break;
                    if(i == md_buf.length) break;
                    iv[iv_ix++] = md_buf[i];
                    niv--;
                    i++;
                }
            }
            if(nkey == 0 && niv == 0) {
                break;
            }
        }
        for(i=0;i<md_buf.length;i++) {
            md_buf[i] = 0;
        }
        return new KeyAndIvImpl(key,iv);
    }
}
