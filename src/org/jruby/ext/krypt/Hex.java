/***** BEGIN LICENSE BLOCK *****
* Version: CPL 1.0/GPL 2.0/LGPL 2.1
*
* The contents of this file are subject to the Common Public
* License Version 1.0 (the "License"); you may not use this file
* except in compliance with the License. You may obtain a copy of
* the License at http://www.eclipse.org/legal/cpl-v10.html
*
* Software distributed under the License is distributed on an "AS
* IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
* implied. See the License for the specific language governing
* rights and limitations under the License.
*
* Copyright (C) 2011-2013
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <Martin.Bosslet@gmail.com>
*
* Alternatively, the contents of this file may be used under the terms of
* either of the GNU General Public License Version 2 or later (the "GPL"),
* or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
* in which case the provisions of the GPL or the LGPL are applicable instead
* of those above. If you wish to allow use of your version of this file only
* under the terms of either the GPL or the LGPL, and not to allow others to
* use your version of this file under the terms of the CPL, indicate your
* decision by deleting the provisions above and replace them with the notice
* and other provisions required by the GPL or the LGPL. If you do not delete
* the provisions above, a recipient may use your version of this file under
* the terms of any one of the CPL, the GPL or the LGPL.
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
    
    public static String encodeAsString(byte[] bytes) {
        try {
            return new String(encode(bytes), "US-ASCII");
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
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
