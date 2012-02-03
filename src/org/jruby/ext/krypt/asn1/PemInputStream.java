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
* Copyright (C) 2011 
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <Martin.Bosslet@googlemail.com>
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
package org.jruby.ext.krypt.asn1;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import org.jruby.ext.krypt.Base64;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class PemInputStream extends FilterInputStream {

    private Base64Buffer b64Buffer;
    private final byte[] singleByte = new byte[1];
    
    public PemInputStream(InputStream in) {
        super(in);
        b64Buffer = new Base64Buffer(in);
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
    
    private static class ParseContext {
        private byte[] buffer;
        private int offset;
        
        public ParseContext(String line) {
            try {
                this.buffer = line.getBytes("US-ASCII");
                this.offset = 0;
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException(ex);
            }
        }
        
        public byte currentByte() {
            return buffer[offset];
        }
        
        public boolean hasNext() {
            return offset < buffer.length - 1;
        }
        
        public byte nextByte() {
            return buffer[++offset];
        }
    }
    
    private interface SingleMatcher {
        public boolean match(ParseContext ctx);
    }
    
    private static final SingleMatcher WHITESPACE = new SingleMatcher() {
        private boolean isWhitespace(byte b) {
            return (b == ' ' || b == '\t');
        }
        
        @Override
        public boolean match(ParseContext ctx) {
            byte b = ctx.currentByte();
            while (isWhitespace(b)) {
                if (!ctx.hasNext())
                    return false;
                b = ctx.nextByte();
            }
            return true;
        }
    };
    
    private static final SingleMatcher SEQ_OF_HYPHENS = new SingleMatcher() {
        @Override
        public boolean match(ParseContext ctx) {
            byte b = ctx.currentByte();
            if (b != '-')
                return false;
            while (b == '-') {
                if (!ctx.hasNext())
                    return false;
                b = ctx.nextByte();
            }
            return true;
        }
    };
    
    private static final SingleMatcher CLOSING_SEQ_OF_HYPHENS = new SingleMatcher() {
        @Override
        public boolean match(ParseContext ctx) {
            byte b = ctx.currentByte();
            if (b != '-')
                return false;
            while (b == '-') {
                if (!ctx.hasNext())
                    return true;
                b = ctx.nextByte();
            }
            if (!WHITESPACE.match(ctx))
                return false;
            return !ctx.hasNext();
        }
    };
    
    private static final SingleMatcher FIND_NEXT_HYPHEN = new SingleMatcher() {
        @Override
        public boolean match(ParseContext ctx) {
            byte b = ctx.currentByte();
            while (b != '-') {
                if (b == '\n')
                    return false;
                if (!ctx.hasNext())
                    return false;
                b = ctx.nextByte();
            }
            return true;
        }
    };
    
    private static final class StringMatcher implements SingleMatcher {
        private final char[] chars;
        
        public StringMatcher(String s) {
            this.chars = s.toCharArray();
        }

        @Override
        public boolean match(ParseContext ctx) {
            byte b = ctx.currentByte();
            
            for (char c : chars) {
                if (b != c)
                    return false;
                if (!ctx.hasNext())
                    return false;
                b = ctx.nextByte();
            }
            return true;
        }
    }    
        
    private static class SequentialMatcher {
        private final List<SingleMatcher> matches;
        private final ParseContext ctx;

        public SequentialMatcher(List<SingleMatcher> matches, ParseContext ctx) {
            this.matches = matches;
            this.ctx = ctx;
        }
        
        public boolean match() {
            for (SingleMatcher single : matches) {
                if (!single.match(ctx))
                    return false;
            }
            return true;
        }
    }
    
    private static abstract class PemLineMatcher {
        private final SequentialMatcher matcher;
        
        public PemLineMatcher(String line, final String beginOrEnd, final String[] label) {
            ParseContext ctx = new ParseContext(line);
            this.matcher = new SequentialMatcher(new ArrayList<SingleMatcher>() {{
                add(WHITESPACE);
                add(SEQ_OF_HYPHENS);
                add(WHITESPACE);
                add(new StringMatcher(beginOrEnd));
                add(WHITESPACE);
                if (label != null) {
                    for (String l : label) {
                        add(new StringMatcher(l));
                        add(WHITESPACE);
                    }
                }
                add(FIND_NEXT_HYPHEN);
                add(CLOSING_SEQ_OF_HYPHENS);
            }}, ctx);
        }
        
        public boolean match() throws IOException {
            return matcher.match();
        }
    }
    
    private static class PemHeaderMatcher extends PemLineMatcher{
        public PemHeaderMatcher(String line) {
            this(line, null);
        }
        
        public PemHeaderMatcher(String line, final String[] label) {
            super(line, "BEGIN", label);
        }
    }
    
    private static class PemFooterMatcher extends PemLineMatcher{
        public PemFooterMatcher(String line) {
            this(line, null);
        }
        
        public PemFooterMatcher(String line, final String[] label) {
            super(line, "END", label);
        }
    }
    
    private static enum State {
        HEADER,
        CONTENT,
        FOOTER
    }
    
    private static class Base64Buffer {
        private static final int THRESHOLD = 4096;
        
        private final BufferedReader in;
        private State state = State.HEADER;
        private String currentLine;
        private byte[] buffer;
        private int bufpos = 0;
        private boolean eof = false;
        
        public Base64Buffer(InputStream in) {
            try {
                this.in = new BufferedReader(new InputStreamReader(in, "US-ASCII"));
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException(ex);
            }
        }
        
        private void readLine() throws IOException {
            currentLine = in.readLine();
        }
        
        private boolean matchHeader() throws IOException {
            while (currentLine != null) {
                if (new PemHeaderMatcher(currentLine).match()) {
                    state = State.CONTENT;
                    readLine();
                    return true;
                }
                readLine();
            }
            return false;
        }
        
        private void matchFooter() throws IOException {
            if (new PemFooterMatcher(currentLine).match()) {
                state = State.HEADER;
                readLine();
            }
            else {
                throw new MalformedPemException("Invalid PEM format");
            }
        }
        
        private void decodeBuffer(byte[] b) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Base64.decodeTo(b, 0, b.length, baos);
            buffer = baos.toByteArray();
            bufpos = 0;
        }
        
        private void fillWithContent() throws IOException {
            int read = 0;
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while (read  < THRESHOLD) {
                if (currentLine == null) {
                    eof = true;
                    break;
                }
                if (currentLine.startsWith("-")) {
                    state = State.FOOTER;
                    break;
                }
                baos.write(currentLine.getBytes());
                read += currentLine.length();
                readLine();
            }
            
            if (read > 0)
                decodeBuffer(baos.toByteArray());
        }
        
        private void fill() throws IOException {
            switch (state) {
                case FOOTER:
                    matchFooter(); /* FALLTHROUGH */
                case HEADER:
                    if (!matchHeader()) {
                        eof = true;
                    }
            }
            if (eof)
                return;
            
            fillWithContent();
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
            if (eof)
                return -1;
            int total = 0;
            if (buffer == null) {
                readLine();
                fill();
                if (buffer == null)
                    throw new MalformedPemException("Invalid PEM format");
            }
            while (total != len && !(bufpos == buffer.length && eof)) {
                if (bufpos == buffer.length)
                    fill();
                total += consumeBytes(b, off, len);
            }
            return total;
        }
    }
    
    public static class MalformedPemException extends RuntimeException {
        public MalformedPemException(Throwable cause) { super(cause); }
        public MalformedPemException(String message, Throwable cause) { super(message, cause); }
        public MalformedPemException(String message) { super(message); }
    }
}
