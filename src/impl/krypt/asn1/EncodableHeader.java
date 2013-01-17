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

import java.io.IOException;
import java.io.OutputStream;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class EncodableHeader implements Header {
    
    private final Tag tag;
    private final Length length;
    
    public EncodableHeader(int tag,
                           TagClass tagClass,
                           boolean isConstructed,
                           boolean isInfinite) {
        this(new Tag(tag, tagClass, isConstructed), new Length(isInfinite));
    }
    
    public EncodableHeader(Tag tag, Length length) {
        if (tag == null) throw new NullPointerException();
        if (length == null) throw new NullPointerException();
        
        this.tag = tag;
        this.length = length;
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

    @Override
    public int getHeaderLength() {
        byte[] tagEncoding = tag.getEncoding();
        byte[] lengthEncoding = length.getEncoding();
        return tagEncoding.length + lengthEncoding.length;
    }

    @Override
    public Length getLength() {
        return length;
    }

    @Override
    public Tag getTag() {
        return tag;
    }
}
