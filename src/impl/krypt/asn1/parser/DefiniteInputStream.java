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

import impl.krypt.asn1.ParseException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
class DefiniteInputStream extends FilterInputStream {

    private int read = 0;
    private final int length;
    
    DefiniteInputStream(InputStream in, int length) {
        super(in);
        if (length < 0) throw new IllegalArgumentException("Length must be positive");
        this.length = length;
    }

    @Override
    public int read() throws IOException {
        if (read == length)
            return -1;
        int b = super.read();
        read++;
        return b;
    }

    @Override
    public void close() throws IOException {
        //do nothing
    }
    
    

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (read == length)
            return -1;
        
        int toRead, actuallyRead;
        
        if (length - read < len)
            toRead = length - read;
        else
            toRead = len;
        
        actuallyRead = super.read(b, off, toRead);
        if (actuallyRead == -1)
            throw new ParseException("Premature end of value detected.");
        
        read += actuallyRead;
        return actuallyRead;
    }

}
