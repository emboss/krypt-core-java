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
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.Parser;
import impl.krypt.asn1.Tag;
import impl.krypt.asn1.TagClass;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
class ChunkInputStream extends FilterInputStream {

    private static enum State {
        NEW_HEADER,
        PROCESS_TAG,
        PROCESS_LENGTH,
        PROCESS_VALUE,
        DONE
    }
    
    private final Parser parser;
    private final boolean valuesOnly;
    
    private ParsedHeader currentHeader;
    private int headerOffset;
    private State state;
    
    ChunkInputStream(InputStream in, Parser parser, boolean valuesOnly) {
        super(in);
        if (parser == null) throw new NullPointerException();
        
        this.parser = parser;
        this.valuesOnly = valuesOnly;
        this.headerOffset = 0;
        this.state = State.NEW_HEADER;
    }

    @Override
    public int read() throws IOException {
        if (State.DONE == state)
            return -1;
        return readSingleByte();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (State.DONE == state)
            return -1;
        return readMultipleBytes(b, off, len);
    }
    
    private int readSingleByte() throws IOException {
        switch (state) {
            case NEW_HEADER: 
                readNewHeader(); //fallthrough
            case PROCESS_TAG: {
                int b = readSingleHeaderByte(currentHeader.getTag().getEncoding(),
                                            State.PROCESS_LENGTH);
                if (!valuesOnly)
                    return b;
            }
            case PROCESS_LENGTH: {
                int b = readSingleHeaderByte(currentHeader.getLength().getEncoding(),
                                              State.PROCESS_VALUE);
                checkDone();
                if (!valuesOnly)
                    return b;
            }
            case PROCESS_VALUE:
                return readSingleValueByte();
            default:
                throw new UnsupportedOperationException(state.name());
        }
    }
    
    private void checkDone() {
        //if state is PROCESS_VALUE, this means that the tag bytes
        //have been consumed. As an EOC contains no value, we are
        //done
        Tag tag = currentHeader.getTag();
        if (tag.getTag() == 0x00 &&
            tag.getTagClass().equals(TagClass.UNIVERSAL) &&
            state == State.PROCESS_VALUE) {
            state = State.DONE;
        }
    }
    
    private int readSingleHeaderByte(byte[] headerPart, State nextState) {
        byte ret = headerPart[headerOffset];
        headerOffset++;
        if (headerOffset == headerPart.length) {
            headerOffset = 0;
            state = nextState;
        }
        return (ret & 0xff);
    }
    
    private int readSingleValueByte() throws IOException {
        int b = currentHeader.getValueStream(valuesOnly).read();
        if (b == -1) {
            state = State.NEW_HEADER;
            b = readSingleByte();
        }
        return b;
    }
    
    private int readMultipleBytes(byte[] b, int off, int len) throws IOException {
        int read, totalRead = 0;
        while (totalRead != len && state != State.DONE) {
            read = readMultipleBytesSingleElement(b, off, len);
            totalRead += read;
            off += read;
        }
        return totalRead;
    }
    
    private int readMultipleBytesSingleElement(byte[] b, int off, int len) throws IOException {
        int read, totalRead = 0;
        
        switch (state) {
            case NEW_HEADER: 
                readNewHeader(); //fallthrough
            case PROCESS_TAG: {
                read = readHeaderBytes(currentHeader.getTag().getEncoding(),
                                       State.PROCESS_LENGTH, b, off, len);
                if (!valuesOnly) {
                    totalRead += read;
                    if (totalRead == len)
                        return totalRead;
                    off += read;
                }
            } //fallthrough
            case PROCESS_LENGTH: {
                read = readHeaderBytes(currentHeader.getLength().getEncoding(),
                                           State.PROCESS_VALUE, b, off, len);
                
                checkDone();
                
                if (!valuesOnly) {
                    totalRead += read;
                    if (totalRead == len || state == State.DONE)
                        return totalRead;
                    off += read;
                }
            } //fallthrough
            case PROCESS_VALUE:
                totalRead += readValueBytes(b, off, len);
                return totalRead;
            default:
                throw new UnsupportedOperationException(state.name());
        }
    }
    
    private int readHeaderBytes(byte[] headerPart, 
                                State nextState,
                                byte[] b,
                                int off,
                                int len) {
        int toRead;
        int available = headerPart.length - headerOffset;
        
        if (len < available) {
            headerOffset += len;
            toRead = len;
        }
        else {
            state = nextState;
            headerOffset = 0;
            toRead = available;
        }
        
        System.arraycopy(headerPart, headerOffset, b, off, toRead);
        return toRead;
    }
    
    private int readValueBytes(byte[] b, int off, int len) throws IOException {
        int read = currentHeader.getValueStream(valuesOnly).read(b, off, len);
        if (read == -1) {
            if (state != State.DONE)
                state = State.NEW_HEADER;
            read = 0;
        }
        return read;
    }
    
    private void readNewHeader() {
        currentHeader = parser.next(in);
        if (currentHeader == null)
            throw new ParseException("Premature end of value detected.");
        state = State.PROCESS_TAG;
        headerOffset = 0;
    }

    @Override
    public void close() throws IOException {
        //do nothing
    }
   
}
