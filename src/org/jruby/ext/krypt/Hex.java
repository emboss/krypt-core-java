/*
 * krypt-core API - Java version
 *
 * Copyright (c) 2011-2013
 * Hiroshi Nakamura <nahi@ruby-lang.org>
 * Martin Bosslet <martin.bosslet@gmail.com>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package org.jruby.ext.krypt;

import java.io.UnsupportedEncodingException;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class Hex {
    
    private Hex() {}
    
    private static final char HEXTABLE[] = "0123456789abcdef".toCharArray();
    private static final byte HEXTABLEINV[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,-1,-1,
    -1,-1,-1,-1,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,10,11,12,
    13,14,15 }; /* 102 */
    
    public static byte[] encode(byte[] bytes) {
        if (bytes == null) throw new NullPointerException("bytes");
        if (bytes.length > Integer.MAX_VALUE / 2) 
            throw new IllegalArgumentException("Too many bytes");
    
        byte[] ret = new byte[2 * bytes.length];

        for (int i=0; i<bytes.length; i++) {
            byte b = bytes[i];
            ret[i*2] = (byte) HEXTABLE[(b & 0xf0) >> 4];
            ret[i*2+1] = (byte) HEXTABLE[b & 0x0f];
        }

        return ret;
    }
    
    public static byte[] decode(byte[] bytes) {
        if (bytes == null) throw new NullPointerException("bytes");
        if (bytes.length % 2 != 0) throw new IllegalArgumentException("Hex data length must be a multiple of 2");

        int retlen = bytes.length / 2;
        byte[] ret = new byte[retlen];

        for (int i=0; i < retlen; i++) {
	    byte c = bytes[i*2];
	    byte d = bytes[i*2+1];
	    if (c < 0 || d < 0 ||
                c > HEXTABLEINV.length || d > HEXTABLEINV.length) {
                throw new IllegalArgumentException("Data contains invalid hex character");
            }
            byte b = HEXTABLEINV[c];
            if (b < 0)
                throw new IllegalArgumentException("Data contains invalid hex character");
            ret[i] = (byte) (b << 4);
            b = HEXTABLEINV[d];
            if (b < 0)
                throw new IllegalArgumentException("Data contains invalid hex character");
            ret[i] |= b;
        }

        return ret;
    }
    
    public static byte[] decodeString(String hex) {
        try {
            return decode(hex.getBytes("US-ASCII"));
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }
}
