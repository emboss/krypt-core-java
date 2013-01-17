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
package impl.krypt.asn1.pem;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jruby.ext.krypt.Base64;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class PemInputStream extends FilterInputStream {

    private Base64Buffer b64Buffer;
    private final byte[] singleByte = new byte[1];
    
    public PemInputStream(InputStream in) {
        super(in);
        b64Buffer = new Base64Buffer(in);
    }
    
    public void continueStream() {
        b64Buffer.continueStream();
    }

    public String getCurrentName() {
        return b64Buffer.getName();
    }
    
    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (len <= 0)
            throw new IllegalArgumentException("Negative or zero length");
        return b64Buffer.read(b, off, len);
    }

    @Override
    public int read() throws IOException {
        int r = read(singleByte);
        while (r == 0) {
            r = read(singleByte);
        }
        if (r == -1)
            return r;
        return (singleByte[0] & 0xff);
    }
    
    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public long skip(long n) throws IOException {
        throw new UnsupportedOperationException("Not implemented yet");
    }
    
    private static abstract class PemLineMatcher {
        private final Pattern pattern;
        private final String line;
        private String name;
        
        public PemLineMatcher(String line, final String beginOrEnd) {
            this.pattern = Pattern.compile("^-----" + beginOrEnd + " (\\w(\\w|\\s)*)-----$");
            this.line = line;
        }
        
        public boolean match() throws IOException {
            Matcher m = pattern.matcher(line);
            if (m.matches()) {
                name = m.group(1);
                if (name == null)
                    return false;
                return true;
            }
            return false;
        }
        
        public String getName() {
            return name;
        }
    }
    
    private static class PemHeaderMatcher extends PemLineMatcher{
        public PemHeaderMatcher(String line) {
            super(line, "BEGIN");
        }
    }
    
    private static class PemFooterMatcher extends PemLineMatcher{
        private final String name;
        
        public PemFooterMatcher(String line, String name) {
            super(line, "END");
            this.name = name;
        }

        @Override
        public boolean match() throws IOException {
            boolean match = super.match();
            if (match && name.equals(getName()))
                return true;
            else
                return false;
        }
    }
    
    private static enum State {
        HEADER,
        CONTENT,
        FOOTER,
        DONE
    }
    
    private static class Base64Buffer {
        private static final int THRESHOLD = 4096;
        
        private final BufferedReader in;
        private State state = State.HEADER;
        private byte[] buffer;
        private int bufpos = 0;
        private boolean eof = false;
        private String name;
        
        public Base64Buffer(InputStream in) {
            try {
                this.in = new BufferedReader(new InputStreamReader(in, "US-ASCII"));
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException(ex);
            }
        }
        
        public void continueStream() {
            this.buffer = null;
            this.name = null;
            this.bufpos = 0;
            this.state = State.HEADER;
            this.eof = false;
        }
        
        private int decodeLine(String line, OutputStream out) throws IOException {
            try {
                byte[] bytes = line.getBytes("US-ASCII");
                Base64.decodeTo(bytes, 0, bytes.length, out);
                return bytes.length;
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException(ex);
            }
        }
        
        private void fill() throws IOException {
            int total = 0;
            ByteArrayOutputStream baos = new ByteArrayOutputStream(THRESHOLD);
            String line = in.readLine();
            
            while (!state.equals(State.DONE) && total < THRESHOLD && line != null) {
                if (line.equals("")) {
                    line = in.readLine();
                    continue;
                }
                switch (state) {
                    case HEADER:
                        if (line.charAt(0) == '-') {
                            PemHeaderMatcher matcher = new PemHeaderMatcher(line);
                            if (matcher.match()) {
                                state = State.CONTENT;
                                name = matcher.getName();
                            }
                        }
                        line = in.readLine();
                        break;
                    case CONTENT:
                        if (line.charAt(0) == '-') {
                            state = State.FOOTER;
                        } else {
                            total += decodeLine(line, baos);
                            if (total < THRESHOLD)
                                line = in.readLine();
                        }
                        break;
                    case FOOTER:
                        if (line.charAt(0) == '-') {
                           PemFooterMatcher matcher = new PemFooterMatcher(line, name);
                            if (matcher.match()) {
                                state = State.DONE;
                            }
                            else {
                                line = in.readLine();
                            }
                        } else {
                            line = in.readLine();
                        }
                        break;
                    default:
                        break;
                }
            }
            
            if (state.equals(State.DONE) || line == null)
                eof = true;
            
            if (line == null && !state.equals(State.DONE)) {
                switch (state) {
                    case HEADER:
                        break; /* means we essentially never read PEM data */
                    case CONTENT:
                        throw new MalformedPemException("PEM data ended prematurely");
                    default:
                        throw new MalformedPemException("Could not find matching footer");
                }
            }
            
            buffer = baos.toByteArray();
            bufpos = 0;
        }
        
        private int consumeBytes(byte[] b, int off, int len) {
            if (bufpos == buffer.length)
                return 0;
            int available = buffer.length - bufpos;
            int toRead = len <  available ? len : available;
            System.arraycopy(buffer, bufpos, b, off, toRead);
            bufpos += toRead;
            return toRead;
        }
        
        public int read(byte[] b, int off, int len) throws IOException {
            int total = 0;
            if (buffer == null) {
                fill();
            }
            while (total != len && !(bufpos == buffer.length && eof)) {
                if (bufpos == buffer.length)
                    fill();
                total += consumeBytes(b, off + total, len - total);
            }
            if (total == 0 && eof)
                return -1;
            return total;
        }

        public String getName() {
            return name;
        }
    }
    
    public static class MalformedPemException extends RuntimeException {
        public MalformedPemException(Throwable cause) { super(cause); }
        public MalformedPemException(String message, Throwable cause) { super(message, cause); }
        public MalformedPemException(String message) { super(message); }
    }
}
