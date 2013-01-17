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
package org.jruby.ext.krypt.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import org.jcodings.specific.UTF8Encoding;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.jruby.Ruby;
import org.jruby.RubyBignum;
import org.jruby.RubyBoolean;
import org.jruby.RubyFixnum;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.asn1.RubyAsn1.Asn1Codec;
import org.jruby.ext.krypt.asn1.RubyAsn1.DecodeContext;
import org.jruby.ext.krypt.asn1.RubyAsn1.EncodeContext;
import org.jruby.ext.krypt.asn1.RubyAsn1.ValidateContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class Asn1Codecs {
    
    private Asn1Codecs() {}
   
    static final Asn1Codec DEFAULT = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            IRubyObject value = ctx.getValue();
            if (value == null || value.isNil()) 
                return null;
            return ctx.getValue().convertToString().getBytes();
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            byte[] value = ctx.getValue();
            Ruby runtime = ctx.getRuntime();
            if (value == null || value.length == 0)
                return runtime.newString();
            else
                return runtime.newString(new ByteList(value, false));
        }

        @Override
        public void validate(ValidateContext ctx) {
            IRubyObject value = ctx.getValue();
            if (value == null || value.isNil()) return;
            if (!(value instanceof RubyString))
                throw Errors.newASN1Error(ctx.getRuntime(), "Value must be a string");
        }
    };
    
    private static final Asn1Codec END_OF_CONTENTS = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            return null;
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            byte[] value = ctx.getValue();
            Ruby runtime = ctx.getRuntime();
            if (!(value == null || value.length == 0))
                throw Errors.newASN1Error(runtime, "Invalid end of contents encoding");
            return runtime.getNil();
        }

        @Override
        public void validate(ValidateContext ctx) {
            if (!ctx.getValue().isNil())
                throw Errors.newASN1Error(ctx.getRuntime(), "Value for END_OF_CONTENTS must be nil");
        }
    };
    
    private static final Asn1Codec BOOLEAN = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            IRubyObject value = ctx.getValue();
            byte[] b = new byte[1];
            if (!value.isTrue())
                b[0] = (byte)0x00;
            else
                b[0] = (byte)0xff;
            return b;
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            byte[] value = ctx.getValue();
            Ruby runtime = ctx.getRuntime();
            if (value == null || value.length != 1)
                throw Errors.newASN1Error(runtime, "Boolean value with length != 1 found");
            if (value[0] == ((byte)0x00))
                return runtime.getFalse();
            else
                return runtime.getTrue();
        }

        @Override
        public void validate(ValidateContext ctx) {
            IRubyObject value = ctx.getValue();
            if (!(value instanceof RubyBoolean))
                throw Errors.newASN1Error(ctx.getRuntime(), "Value for BOOLEAN must be either true or false");
        }
    };
    
    private static final Asn1Codec INTEGER = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            IRubyObject value = ctx.getValue();
            Ruby runtime = ctx.getRuntime();
            if (value instanceof RubyFixnum) {
                return BigInteger.valueOf(RubyNumeric.num2long(value)).toByteArray();
            } else if (value instanceof RubyBignum) {
                BigInteger big = ((RubyBignum)value).getValue();
                return big.toByteArray();
            } else {
                throw Errors.newASN1Error(runtime, "Value is not a number");
            }
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            byte[] value = ctx.getValue();
            Ruby runtime = ctx.getRuntime();
            if (value == null)
                throw Errors.newASN1Error(runtime, "Invalid integer encoding");
            return RubyBignum.newBignum(runtime, new BigInteger(value));
        }

        @Override
        public void validate(ValidateContext ctx) {
            IRubyObject value = ctx.getValue();
            if (!(value instanceof RubyFixnum || value instanceof RubyBignum))
                throw Errors.newASN1Error(ctx.getRuntime(), "Value for integer type must be an integer Number");
        }
    };
    
    private static final Asn1Codec BIT_STRING = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            IRubyObject recv = ctx.getReceiver();
            IRubyObject value = ctx.getValue();
            IRubyObject unusedBitsIv = recv.getInstanceVariables().getInstanceVariable("unused_bits");
            int unusedBits = RubyNumeric.fix2int(unusedBitsIv);
            checkUnusedBits(ctx.getRuntime(), unusedBits);
            byte[] bytes = value.convertToString().getBytes();
            byte[] ret = new byte[bytes.length + 1];
            ret[0] = (byte)(unusedBits & 0xff);
            System.arraycopy(bytes, 0, ret, 1, bytes.length);
            return ret;
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            byte[] value = ctx.getValue();
            Ruby runtime = ctx.getRuntime();
            IRubyObject recv = ctx.getReceiver();
            if (value == null)
                throw Errors.newASN1Error(runtime, "Invalid BIT STRING encoding");
            int unusedBits = value[0] & 0xff;
            checkUnusedBits(runtime, unusedBits);
            IRubyObject ret = runtime.newString(new ByteList(value, 1, value.length - 1, false));
            recv.getInstanceVariables().setInstanceVariable("unused_bits", RubyNumeric.int2fix(runtime, unusedBits));
            return ret;
        }
        
        @Override
        public void validate(ValidateContext ctx) {
            if (ctx.getValue().isNil())
                throw Errors.newASN1Error(ctx.getRuntime(), "BIT STRING value cannot be empty");
            DEFAULT.validate(ctx);
        }
        
        
    };
    
    private static void checkUnusedBits(Ruby runtime, int unusedBits) {
        if (unusedBits < 0 || unusedBits > 7)
            throw Errors.newASN1Error(runtime, "Unused bits must be 0..7");
    }
    
    private static final Asn1Codec OCTET_STRING = DEFAULT;
    
    private static final Asn1Codec NULL = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            return null;
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            byte[] value = ctx.getValue();
            Ruby runtime = ctx.getRuntime();
            if (!(value == null || value.length == 0))
                throw Errors.newASN1Error(runtime, "Invalid null encoding");
            return runtime.getNil();
        }

        @Override
        public void validate(ValidateContext ctx) {
            IRubyObject value = ctx.getValue();
            if (!(value == null || value.isNil()))
                throw Errors.newASN1Error(ctx.getRuntime(), "Value must be nil for NULL");
        }
    };
    
    private static final Asn1Codec OBJECT_ID = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            Ruby runtime = ctx.getRuntime();
            IRubyObject value = ctx.getValue();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            long first, second, cur;
            ObjectIdEncodeContext oidctx = new ObjectIdEncodeContext(value.convertToString().getBytes(), runtime);
            
            if ((first = oidctx.nextSubId()) == -1)
                throw Errors.newASN1Error(runtime, "Error while encoding object identifier");
            if ((second = oidctx.nextSubId()) == -1)
                throw Errors.newASN1Error(runtime, "Error while encoding object identifier");
            checkFirstSubId(runtime, first);
            checkSecondSubId(runtime, second);

            cur = 40 * first + second;
            
            try {
                writeLong(baos, cur);

                while ((cur = oidctx.nextSubId()) != -1) {
                    writeLong(baos, cur);
                }
            } catch (IOException ex) {
                throw Errors.newASN1Error(runtime, ex.getMessage());
            }
            
            return baos.toByteArray();
        }
        
        @Override
        public IRubyObject decode(DecodeContext ctx) {
            byte[] value = ctx.getValue();
            Ruby runtime = ctx.getRuntime();
            if (value == null)
                throw Errors.newASN1Error(runtime, "Invalid object id encoding");
            long first, second, cur;
            ObjectIdParseContext oidctx = new ObjectIdParseContext(value, runtime);
            StringBuilder builder = new StringBuilder();
            
            if ((cur = oidctx.parseNext()) == -1)
                throw Errors.newASN1Error(runtime, "Error while parsing object identifier");
            if (cur > 40 * 2 + 39)
                throw Errors.newASN1Error(runtime, "Illegal first octet, value too large");
            first = determineFirst(cur);
            second = cur - 40 * first;
            checkFirstSubId(runtime, first);
            checkSecondSubId(runtime, second);
            builder.append(String.valueOf(first));
            appendNumber(builder, second);
            
            while ((cur = oidctx.parseNext()) != -1)
                appendNumber(builder, cur);
            
            return runtime.newString(new ByteList(builder.toString().getBytes()));
        }
        
        private void appendNumber(StringBuilder b, long cur) {
            b.append('.')
             .append(String.valueOf(cur));
        }
        
        private long determineFirst(long combined) {
            long f = 1;
            while (40 * f <= combined)
                f++;
            return f - 1;
        }
        
        private void checkFirstSubId(Ruby runtime, long first) {
            if (first > 2)
                throw Errors.newASN1Error(runtime, "First sub id must be 0..2");
        }

        private void checkSecondSubId(Ruby runtime, long second) {
            if (second > 39)
                throw Errors.newASN1Error(runtime, "Second sub id must be 0..39");
        }
        
        @Override
        public void validate(ValidateContext ctx) {
            if (!(ctx.getValue() instanceof RubyString))
                throw Errors.newASN1Error(ctx.getRuntime(), "Value for OBJECT IDENTIFIER must be a String");
        }
    };
    
    static int determineNumberOfShifts(long value, int shiftBy) {
        int i;
        for (i = 0; value > 0; i++) {
            value >>= shiftBy;
        }
        return i;
    }
    
    private static void writeLong(ByteArrayOutputStream baos, long cur) throws IOException {
        if (cur == 0) {
            baos.write(0);
            return;
        }

        int numShifts = determineNumberOfShifts(cur, 7);
        byte[] bytes = new byte[numShifts];

        for (int i = numShifts - 1; i >= 0; i--) {
            byte b = (byte)(cur & 0x7f);
            if (i < numShifts - 1)
                b |= 0x80;
            bytes[i] = b;
            cur >>= 7;
        }

        baos.write(bytes);
    }
    
    private static final Asn1Codec ENUMERATED = INTEGER;
    
    private static final Asn1Codec UTF8_STRING = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            IRubyObject value = ctx.getValue();
            if (value.isNil())
                return null;
            RubyString s = value.convertToString();
            s.associateEncoding(UTF8Encoding.INSTANCE);
            return s.getBytes();
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            IRubyObject obj = DEFAULT.decode(ctx);
            obj.asString().associateEncoding(UTF8Encoding.INSTANCE);
            return obj;
        }

        @Override
        public void validate(ValidateContext ctx) {
            DEFAULT.validate(ctx);
        }
    };
    
    private static final DateTimeFormatter UTC_FORMATTER = DateTimeFormat.forPattern("yyMMddHHmmss'Z'").withZone(DateTimeZone.UTC);
    private static final DateTimeFormatter GT_FORMATTER = DateTimeFormat.forPattern("yyyyMMddHHmmss'Z'").withZone(DateTimeZone.UTC);
    
    private static byte[] encodeTime(Ruby runtime, IRubyObject value, DateTimeFormatter formatter) {
        if (value instanceof RubyTime)
            return encodeRubyTime(runtime, value, formatter);
        else return encodeFixnumTime(runtime, value, formatter);
    }
    
    private static byte[] encodeRubyTime(Ruby runtime, IRubyObject value, DateTimeFormatter formatter) {
        try {
            return ((RubyTime)value).getDateTime()
                                .toString(formatter)
                                .getBytes();
        } catch (Exception ex) {
            throw Errors.newASN1Error(runtime, "Error while encoding time value: " + ex.getMessage());
        }
    }
    
    private static byte[] encodeFixnumTime(Ruby runtime, IRubyObject value, DateTimeFormatter formatter) {
        try {
            long val = RubyNumeric.num2long(value);
            if (val < 0)
                throw Errors.newASN1Error(runtime, "Negative time value given");
            /* Ruby time is *seconds* since the epoch */
            DateTime dt = new DateTime(val * 1000, DateTimeZone.UTC);
            return dt.toString(formatter).getBytes();
        } catch (Exception ex) {
            throw Errors.newASN1Error(runtime, "Error while encoding time value: " + ex.getMessage());
        }
    }
    
    private static IRubyObject decodeTime(Ruby runtime, byte[] value, DateTimeFormatter formatter) {
        if (value == null)
            throw Errors.newASN1Error(runtime, "Invalid time encoding");
        try {
            DateTime dateTime = formatter.parseDateTime(new String(value, Charset.forName("US-ASCII")));
            return RubyTime.newTime(runtime, dateTime);
        } catch (Exception ex) {
            throw Errors.newASN1Error(runtime, "Error while decoding time value: " + ex.getMessage());
        }
    }
    
    private static void validateTime(ValidateContext ctx) {
        IRubyObject value = ctx.getValue();
        if (!(value instanceof RubyTime || value instanceof RubyFixnum || value instanceof RubyString))
            throw Errors.newASN1Error(ctx.getRuntime(), "Time type must be either a Time, a Fixnum or a String");
    }
    
    private static final Asn1Codec UTC_TIME = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            return encodeTime(ctx.getRuntime(), ctx.getValue(), UTC_FORMATTER);
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            return decodeTime(ctx.getRuntime(), ctx.getValue(), UTC_FORMATTER);
        }

        @Override
        public void validate(ValidateContext ctx) {
            validateTime(ctx);
        }
    };
    
    private static final Asn1Codec GENERALIZED_TIME = new Asn1Codec() {

        @Override
        public byte[] encode(EncodeContext ctx) {
            return encodeTime(ctx.getRuntime(), ctx.getValue(), GT_FORMATTER);
        }

        @Override
        public IRubyObject decode(DecodeContext ctx) {
            return decodeTime(ctx.getRuntime(), ctx.getValue(), GT_FORMATTER);
        }

        @Override
        public void validate(ValidateContext ctx) {
            validateTime(ctx);
        }
    };
    
    static Asn1Codec[] CODECS = new Asn1Codec[] {
        END_OF_CONTENTS,
        BOOLEAN,
        INTEGER,
        BIT_STRING,
        OCTET_STRING,
        NULL,
        OBJECT_ID,
        null,
        null,
        null,
        ENUMERATED,
        null,
        UTF8_STRING,
        null,
        null,
        null,
        null,
        null,
        OCTET_STRING,
        OCTET_STRING,
        OCTET_STRING,
        OCTET_STRING,
        OCTET_STRING,
        UTC_TIME,
        GENERALIZED_TIME,
        OCTET_STRING,
        OCTET_STRING,
        OCTET_STRING,
        OCTET_STRING,
        OCTET_STRING,
        OCTET_STRING
    };
    
    private static class ObjectIdEncodeContext {
        private final byte[] raw;
        private final Ruby runtime;
        private int offset = 0;

        private static long ENCODE_LIMIT = Long.MAX_VALUE / 10;

        public ObjectIdEncodeContext(byte[] raw, Ruby runtime) {
            this.raw = raw;
            this.runtime = runtime;
        }
        
        public final long nextSubId() {
            if (offset >= raw.length)
                return -1;
            
            long ret = 0;
            
            char c = (char) (raw[offset] & 0xff);
            if (c == '.')
                throw Errors.newASN1Error(runtime, "Sub identifier cannot start with '.'");
            
            while (offset < raw.length && (c = (char) (raw[offset] & 0xff)) != '.' ) {
                if (c < '0' || c > '9')
                    throw Errors.newASN1Error(runtime, "Invalid character in object identifer: " + c);
                if (ret > ENCODE_LIMIT)
                    throw Errors.newASN1Error(runtime, "Sub object identifier too large");
                if (offset + 1 == Long.MAX_VALUE)
                    throw Errors.newASN1Error(runtime, "Object id value too large");
                
                ret *= 10;
                ret += c - '0';
                offset++;
            }
            
            offset++; /* skip '.' */
            return ret;
        }
    }
    
    private static class ObjectIdParseContext {
        private final byte[] raw;
        private final Ruby runtime;
        int offset = 0;

        private static long LIMIT_PARSE = Long.MAX_VALUE >> 7;
        
        public ObjectIdParseContext(byte[] raw, Ruby runtime) {
            this.raw = raw;
            this.runtime = runtime;
        }
        
        public long parseNext() {
            long num = 0;
            
            if (offset >= raw.length)
                return -1;
            
            while ((raw[offset] & 0x80) > 0) {
                if (num > LIMIT_PARSE)
                    throw Errors.newASN1Error(runtime, "Sub identifier too large");
                num <<= 7;
                num |= raw[offset++] & 0x7f;
                if (offset >= raw.length)
                    throw Errors.newASN1Error(runtime, "Invalid object identifier encoding");
            }
            
            num <<= 7;
            num |= raw[offset++] & 0x7f;
            
            return num;
        }
    }
}
