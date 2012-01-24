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
import org.jruby.RubyFixnum;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.RubyTime;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.asn1.Asn1.Asn1Codec;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.marshal.MarshalStream;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Asn1Codecs {
    
    private Asn1Codecs() {}
   
    static final Asn1Codec DEFAULT = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            return value.convertToString().getBytes();
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            if (value == null)
                return runtime.getNil();
            else
                return runtime.newString(new ByteList(value, false));
        }
    };
    
    private static final Asn1Codec END_OF_CONTENTS = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            return null;
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            if (!(value == null || value.length == 0))
                throw Errors.newAsn1Error(runtime, "Invalid end of contents encoding");
            return runtime.getNil();
        }
    };
    
    private static final Asn1Codec BOOLEAN = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            byte[] b = new byte[1];
            if (!value.isTrue())
                b[0] = (byte)0x00;
            else
                b[0] = (byte)0xff;
            return b;
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            if (value == null || value.length != 1)
                throw Errors.newAsn1Error(runtime, "Boolean value with length != 1 found");
            if (value[0] == ((byte)0x00))
                return runtime.getFalse();
            else
                return runtime.getTrue();
        }
    };
    
    private static final Asn1Codec INTEGER = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            if (value instanceof RubyFixnum) {
                return BigInteger.valueOf(RubyNumeric.num2long(value)).toByteArray();
            } else if (value instanceof RubyBignum) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    MarshalStream ms = new MarshalStream(runtime, baos, -1);
                    RubyBignum.marshalTo((RubyBignum)value, ms);
                    return baos.toByteArray();
                } catch (IOException ex) {
                    throw Errors.newAsn1Error(runtime, ex.getMessage());
                }
            } else {
                throw Errors.newAsn1Error(runtime, "Value is not a number");
            }
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            if (value == null)
                throw Errors.newAsn1Error(runtime, "Invalid integer encoding");
            return RubyBignum.newBignum(runtime, new BigInteger(value));
        }
    };
    
    private static final Asn1Codec BIT_STRING = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            IRubyObject unusedBitsIv = value.getInstanceVariables().getInstanceVariable("unused_bits");
            int unusedBits = RubyNumeric.fix2int(unusedBitsIv);
            byte[] bytes = value.convertToString().getBytes();
            byte[] ret = new byte[bytes.length + 1];
            ret[0] = (byte)(unusedBits & 0xff);
            System.arraycopy(bytes, 0, ret, 1, bytes.length);
            return ret;
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            if (value == null)
                throw Errors.newAsn1Error(runtime, "Invalid bit string encoding");
            int unusedBits = value[0] & 0xff;
            IRubyObject ret = runtime.newString(new ByteList(value, 1, value.length - 1));
            ret.getInstanceVariables().setInstanceVariable("unused_bits", RubyNumeric.int2fix(runtime, unusedBits));
            return ret;
        }
    };
    
    private static final Asn1Codec OCTET_STRING = DEFAULT;
    
    private static final Asn1Codec NULL = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            return null;
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            if (!(value == null || value.length == 0))
                throw Errors.newAsn1Error(runtime, "Invalid null encoding");
            return runtime.getNil();
        }
    };
    
    private static final Asn1Codec OBJECT_ID = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            long first, second, cur;
            ObjectIdEncodeContext ctx = new ObjectIdEncodeContext(value.convertToString().getBytes(), runtime);
            
            if ((first = ctx.nextSubId()) == -1)
                throw Errors.newAsn1Error(runtime, "Error while encoding object identifier");
            if ((second = ctx.nextSubId()) == -1)
                throw Errors.newAsn1Error(runtime, "Error while encoding object identifier");
    
            cur = 40 * first + second;
            
            try {
                writeLong(baos, cur);

                while ((cur = ctx.nextSubId()) != -1) {
                    writeLong(baos, cur);
                }
            } catch (IOException ex) {
                throw Errors.newAsn1Error(runtime, ex.getMessage());
            }
            
            return baos.toByteArray();
        }
        
        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            if (value == null)
                throw Errors.newAsn1Error(runtime, "Invalid object id encoding");
            long first, second, cur;
            ObjectIdParseContext ctx = new ObjectIdParseContext(value, runtime);
            StringBuilder builder = new StringBuilder();
            
            if ((cur = ctx.parseNext()) == -1)
                throw Errors.newAsn1Error(runtime, "Error while parsing object identifier");
            first = determineFirst(cur);
            second = cur - 40 * first;
            builder.append(String.valueOf(first));
            appendNumber(builder, second);
            
            while ((cur = ctx.parseNext()) != -1)
                appendNumber(builder, cur);
            
            return runtime.newString(new ByteList(builder.toString().getBytes()));
        }
        
        private void appendNumber(StringBuilder b, long cur) {
            b.append('.')
             .append(String.valueOf(cur));
        }
        
        private long determineFirst(long combined) {
            long f = 1;
            while (40 * f < combined)
                f++;
            return f - 1;
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
        public byte[] encode(Ruby runtime, IRubyObject value) {
            RubyString s = value.convertToString();
            s.associateEncoding(UTF8Encoding.INSTANCE);
            return s.getBytes();
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            IRubyObject obj = DEFAULT.decode(runtime, value);
            obj.asString().associateEncoding(UTF8Encoding.INSTANCE);
            return obj;
        }
    };
    
    private static final DateTimeFormatter UTC_FORMATTER = DateTimeFormat.forPattern("yyMMddHHmmss'Z'").withZone(DateTimeZone.UTC);
    private static final DateTimeFormatter GT_FORMATTER = DateTimeFormat.forPattern("yyyyMMddHHmmss'Z'").withZone(DateTimeZone.UTC);
    
    private static byte[] encodeTime(Ruby runtime, IRubyObject value, DateTimeFormatter formatter) {
        if (!(value instanceof RubyTime))
            throw Errors.newAsn1Error(runtime, "Value is not a time");
        return ((RubyTime)value).getDateTime()
                                .toString(formatter)
                                .getBytes();
    }
    
    private static IRubyObject decodeTime(Ruby runtime, byte[] value, DateTimeFormatter formatter) {
        if (value == null)
            throw Errors.newAsn1Error(runtime, "Invalid time encoding");
        DateTime dateTime = formatter.parseDateTime(new String(value, Charset.forName("US-ASCII")));
        return RubyTime.newTime(runtime, dateTime);
    }
    
    private static final Asn1Codec UTC_TIME = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            return encodeTime(runtime, value, UTC_FORMATTER);
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            return decodeTime(runtime, value, UTC_FORMATTER);
        }
    };
    
    private static final Asn1Codec GENERALIZED_TIME = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            return encodeTime(runtime, value, GT_FORMATTER);
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            return decodeTime(runtime, value, GT_FORMATTER);
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
                throw Errors.newAsn1Error(runtime, "Sub identifier cannot start with '.'");
            
            while (offset < raw.length && (c = (char) (raw[offset] & 0xff)) != '.' ) {
                if (c < '0' || c > '9')
                    throw Errors.newAsn1Error(runtime, "Invalid character in object identifer: " + c);
                if (ret > ENCODE_LIMIT)
                    throw Errors.newAsn1Error(runtime, "Sub object identifier too large");
                if (offset + 1 == Long.MAX_VALUE)
                    throw Errors.newAsn1Error(runtime, "Object id value too large");
                
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
                    throw Errors.newAsn1Error(runtime, "Sub identifier too large");
                num <<= 7;
                num |= raw[offset++] & 0x7f;
                if (offset >= raw.length)
                    throw Errors.newAsn1Error(runtime, "Invalid object identifier encoding");
            }
            
            num <<= 7;
            num |= raw[offset++] & 0x7f;
            
            return num;
        }
    }
}
