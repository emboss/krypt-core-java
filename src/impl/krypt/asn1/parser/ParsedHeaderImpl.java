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

import impl.krypt.asn1.Asn1Object;
import impl.krypt.asn1.EncodableHeader;
import impl.krypt.asn1.Header;
import impl.krypt.asn1.Length;
import impl.krypt.asn1.ParseException;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.SerializeException;
import impl.krypt.asn1.Tag;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
class ParsedHeaderImpl implements ParsedHeader {

    private final Tag tag;
    private final Length length;
    private final InputStream in;
    private final PullHeaderParser parser;
    
    private byte[] cachedValue;
    private InputStream cachedValueStream;
    private boolean consumed = false;

    ParsedHeaderImpl(Tag tag, 
                     Length length, 
                     InputStream in,
                     PullHeaderParser parser) {
        if (tag == null) throw new NullPointerException();
        if (length == null) throw new NullPointerException();
        if (in == null) throw new NullPointerException();
        if (parser == null) throw new NullPointerException();
        
	this.tag = tag;
	this.length = length;
	this.in = in;
        this.parser = parser;
   }

    @Override
    public void skipValue() {
	getValue();
    }

    @Override
    public byte[] getValue() {
	if (cachedValue == null) {
            if (consumed)
                throw new ParseException("The stream has already been consumed");
            
            InputStream stream = getValueStream(false);
            byte[] ret = doGetValue(stream);
            cachedValue = ret.length == 0 ? null : ret;
            cachedValueStream = null;
            consumed = true;
        }
        return cachedValue;
    }
    
    private byte[] doGetValue(InputStream stream) {
        try {
            return consume(stream);
        }
        finally {
            try {
                stream.close();
            }
            catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    @Override
    public InputStream getValueStream(boolean valuesOnly) {
        if (consumed && cachedValueStream == null)
            throw new ParseException("The stream is already consumed");
        
        if (cachedValueStream == null) {
            cachedValueStream = cacheStream(valuesOnly);
            consumed = true;
        }
        
        return cachedValueStream;
    }
    
    private InputStream cacheStream(boolean valuesOnly) {
        if (length.isInfiniteLength())
            return new ChunkInputStream(in, parser, valuesOnly);
        else
            return new DefiniteInputStream(in, length.getLength());
    }

    private byte[] consume(InputStream stream) {
        
        byte[] buf = new byte[8192];
        int read;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
            while ((read = stream.read(buf)) != -1) {
                baos.write(buf, 0, read);
            }
        }
        catch (IOException ex) {
                throw new ParseException(ex);
        }
        
        return baos.toByteArray();
    }

    @Override
    public Length getLength() {
        return length;
    }

    @Override
    public Tag getTag() {
        return tag;
    }
    
    @Override
    public int getHeaderLength() {
	return tag.getEncoding().length + length.getEncoding().length;
    }

    @Override
    public Asn1Object getObject() {
        Header h = new EncodableHeader(tag, length);
        return new Asn1Object(h, getValue());
    }
    
    @Override
    public void encodeTo(OutputStream out) {
	try {
            out.write(tag.getEncoding());
            out.write(length.getEncoding());
        }
        catch (IOException ex) {
            throw new SerializeException(ex);
        }
    }
}
