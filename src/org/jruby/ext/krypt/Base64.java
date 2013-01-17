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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class Base64 {
    
    private Base64() {}
    
    private static final char B64TABLE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    private static final byte B64TABLEINV[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,
    -1,-1,-1,-1,-1,-1,
    26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
    private static final byte[] SEPARATOR = new byte[] { '\r', '\n' };

    private static void writeInt(int n, OutputStream out) throws IOException {
        out.write(B64TABLE[(n >> 18) & 0x3f]);
        out.write(B64TABLE[(n >> 12) & 0x3f]);
        out.write(B64TABLE[(n >> 6) & 0x3f]);
        out.write(B64TABLE[n & 0x3f]);
    }
    
    private static int computeInt(byte[] bytes, int i) {
        return (bytes[i] & 0xff) << 16 | (bytes[i + 1] & 0xff) << 8 | (bytes[i + 2] & 0xff);
    }
    
    private static void encodeUpdate(byte[] bytes, int off, int until, OutputStream out, int cols) throws IOException {
        int linePos = 0;
        for (int i = 0; i < until; i += 3) {
            writeInt(computeInt(bytes, off + i), out);
            linePos += 4;
            if (linePos >= cols) {
                out.write(SEPARATOR);
                linePos = 0;
            }
        }
    }
    
    private static void encodeUpdate(byte[] bytes, int off, int until, OutputStream out) throws IOException {
        for (int i = 0; i < until; i += 3) {
            writeInt(computeInt(bytes, off + i), out);
        }
    }
    
    private static void encodeFinal(byte[] bytes, int off, int len, OutputStream out, int remainder, boolean crlf) throws IOException {
        off = off + len - remainder;
        if (remainder != 0) {
            int n = bytes[off] << 16 | 
                (remainder == 2 ? bytes[off + 1] << 8 : 0);
            out.write(B64TABLE[(n >> 18) & 0x3f]);
            out.write(B64TABLE[(n >> 12) & 0x3f]);
            out.write(remainder == 2 ? B64TABLE[(n >> 6) & 0x3f] : '=');
            out.write('=');
        }
        if (crlf)
            out.write(SEPARATOR);
    }
    
    public static void encodeTo(byte[] bytes, int off, int len, OutputStream out, int cols) throws IOException {
        if (bytes == null)
            throw new NullPointerException("bytes null");

        int remainder = bytes.length % 3;
        if (cols < 0)
            encodeUpdate(bytes, off, len - remainder, out);
        else
            encodeUpdate(bytes, off, len - remainder, out, cols);
           
        encodeFinal(bytes, off, len, out, remainder, cols > 0);
    }

    public static String encodeAsString(byte[] bytes, int cols) throws IOException {
        try {
            return new String(encode(bytes, cols), "US-ASCII");
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public static byte[] encode(byte[] bytes, int cols) throws IOException {
        if (bytes == null)
            throw new NullPointerException("bytes null");

        /* four thirds the output size plus the number of CRLFs */
        long retlen = (long) (4.0 * Math.ceil((double) bytes.length / 3.0));
        if (cols > 0)
            retlen += bytes.length / cols * 2;

        if (retlen > Integer.MAX_VALUE)
            retlen = Integer.MAX_VALUE;

        ByteArrayOutputStream baos = new ByteArrayOutputStream((int)retlen);
        encodeTo(bytes, 0, bytes.length, baos, cols);

        return baos.toByteArray();
    }
    
    private static void decodeInt(int n, OutputStream out) throws IOException {
        out.write((n >> 16) & 0xff);
        out.write((n >> 8) & 0xff);
        out.write(n & 0xff);
    }
    
    private static void decodeFinalInt(int n, OutputStream out, int remainder) throws IOException {
        switch (remainder) {
            /* 2 of 4 bytes are to be discarded. 
             * 2 bytes represent 12 bits of meaningful data -> 1 byte plus 4 bits to be dropped */ 
            case 2:
                out.write(((n >> 4) & 0xff));
                break;
            /* 1 of 4 bytes are to be discarded.
             * 3 bytes represent 18 bits of meaningful data -> 2 bytes plus 2 bits to be dropped */
            case 3:
                n >>= 2;
                out.write((n >> 8) & 0xff);
                out.write(n & 0xff);
                break;
        }
    }
    
    public static void decodeTo(byte[] in, int off, int len, OutputStream out) throws IOException {
        int i, idx, n = 0;
        int remainder = 0;
        
        for (i=0; i < len; i++) {
            byte b = in[off + i];
            if (b == '=') {
                break;
            }
            idx = b & 0xff;
            if (idx >= B64TABLEINV.length)
                continue;
            byte inv = B64TABLEINV[idx];
            if (inv < 0)
                continue;
            n = (n << 6) | inv; 
            remainder = (remainder + 1) % 4;
            if (remainder == 0) {
                decodeInt(n, out);
            }
        }

        decodeFinalInt(n, out, remainder);
    }
    
    public static byte[] decodeString(String b64String) throws IOException {
        try {
            return decode(b64String.getBytes("US-ASCII"));
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public static byte[] decode(byte[] bytes) throws IOException {
        if (bytes == null)
            throw new NullPointerException("bytes null");
        
        int retlen = bytes.length / 4 * 3;
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream(retlen);
        decodeTo(bytes, 0, bytes.length, baos);
        return baos.toByteArray();
    }
}

