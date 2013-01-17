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
package impl.krypt.asn1;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
class Tags {
    
    private Tags() {}

    public static final byte END_OF_CONTENTS   = (byte)0x00;
    public static final byte BOOLEAN           = (byte)0x01;
    public static final byte INTEGER           = (byte)0x02;
    public static final byte BIT_STRING        = (byte)0x03;
    public static final byte OCTET_STRING      = (byte)0x04;
    public static final byte NULL              = (byte)0x05;
    public static final byte OBJECT_ID         = (byte)0x06;
    
    public static final byte ENUMERATED        = (byte)0x0a;
    
    public static final byte UTF8_STRING       = (byte)0x0c;
    
    public static final byte SEQUENCE          = (byte)0x10;
    public static final byte SET               = (byte)0x11;
    public static final byte NUMERIC_STRING    = (byte)0x12;
    public static final byte PRINTABLE_STRING  = (byte)0x13;
    public static final byte T61_STRING        = (byte)0x14;
    public static final byte VIDEOTEX_STRING   = (byte)0x15;
    public static final byte IA5_STRING        = (byte)0x16;
    public static final byte UTC_TIME          = (byte)0x17;
    public static final byte GENERALIZED_TIME  = (byte)0x18;
    public static final byte GRAPHIC_STRING    = (byte)0x19;
    public static final byte ISO64_STRING      = (byte)0x1a;
    public static final byte GENERAL_STRING    = (byte)0x1b;
    public static final byte UNIVERSAL_STRING  = (byte)0x1c;
    
    public static final byte BMP_STRING        = (byte)0x1e;

}
