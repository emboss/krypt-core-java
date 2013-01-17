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
