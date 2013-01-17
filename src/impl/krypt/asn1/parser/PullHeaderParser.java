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
package impl.krypt.asn1.parser;

import impl.krypt.asn1.Header;
import impl.krypt.asn1.Length;
import impl.krypt.asn1.ParseException;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.Parser;
import impl.krypt.asn1.Tag;
import impl.krypt.asn1.TagClass;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class PullHeaderParser implements Parser {

    private static final int MAX_TAG = Integer.MAX_VALUE >> 7;
    private static final int MAX_LENGTH = Integer.MAX_VALUE >> 8;
    
    public PullHeaderParser() { }
    
    @Override
    public ParsedHeader next(InputStream in) {
        if (in == null) throw new NullPointerException();
        
        int read = nextInt(in);
        if (read == -1) 
            return null;
        byte b = (byte)read;
        Tag tag = parseTag(b, in);
	Length length = parseLength(in);
        
        if (length.isInfiniteLength() && !tag.isConstructed())
            throw new ParseException("Infinite length values must be constructed");
        
	return new ParsedHeaderImpl(tag, length, in, this);
    }
    
    private byte nextByte(InputStream in) {
        int read = nextInt(in);
        if (read == -1) 
            throw new ParseException("EOF reached.");
        return (byte)read;
    }
    
    private int nextInt(InputStream in) {
        try {
            return in.read();
        }
        catch (IOException ex) {
            throw new ParseException(ex);
        }
    }
    
    private static boolean matchMask(byte test, byte mask) {
        return ((byte)(test & mask)) == mask;
    }
    
    private Tag parseTag(byte b, InputStream in) {
        if (matchMask(b, Header.COMPLEX_TAG_MASK))
            return parseComplexTag(b, in);
        else
            return parsePrimitiveTag(b);
    }
    
    private Tag parsePrimitiveTag(byte b) {
        int tag = b & Header.COMPLEX_TAG_MASK;
        boolean isConstructed = matchMask(b, Header.CONSTRUCTED_MASK);
        TagClass tc = TagClass.of((byte)(b & TagClass.PRIVATE.getMask()));
        return new Tag(tag, tc, isConstructed, new byte[] { b });
    }
    
    private Tag parseComplexTag(byte b, InputStream in) {
        boolean isConstructed = matchMask(b, Header.CONSTRUCTED_MASK);
        TagClass tc = TagClass.of((byte)(b & TagClass.PRIVATE.getMask()));
        int tag = 0;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        baos.write(b & 0xff);
        b = nextByte(in);
        if (b == Header.INFINITE_LENGTH_MASK)
            throw new ParseException("Bits 7 to 1 of the first subsequent octet shall not be 0 for complex tag encodings");

        while (matchMask(b, Header.INFINITE_LENGTH_MASK)) {
            if (tag > (MAX_TAG))
                throw new ParseException("Complex tag too long.");
            tag <<= 7;
            tag |= (b & 0x7f);
            baos.write(b & 0xff);
            b = nextByte(in);
        }

        //final byte
        tag <<= 7;
        tag |= (b & 0x7f);
        baos.write(b & 0xff);

        return new Tag(tag, tc, isConstructed, baos.toByteArray());
    }
    
    private Length parseLength(InputStream in) {
	byte b = nextByte(in);
	
        if (b == Header.INFINITE_LENGTH_MASK)
            return new Length(0, true, new byte[] { b });
        else if (matchMask(b, Header.INFINITE_LENGTH_MASK))
            return parseComplexDefiniteLength(b, in);
        else
            return new Length(b & 0xff, false, new byte[] { b });
    }
    
    private Length parseComplexDefiniteLength(byte b, InputStream in) {
        int len = 0;
        int numOctets = b & 0x7f;
        int off = 0;
        
        if ((b & 0xff) == 0xff)
            throw new ParseException("Initial octet of complex definite length shall not be 0xFF");
        
        
        byte[] encoding = new byte[numOctets+1];
        encoding[off++] = b;
        
        for (int i=numOctets; i > 0; i--) {
            if (numOctets > MAX_LENGTH)
                throw new ParseException("Definite value length too long.");
            b = nextByte(in);
            len <<= 8;
            len |= (b & 0xff);
            encoding[off++] = b;
        }
        
        return new Length(len, false, encoding);
    }
}
