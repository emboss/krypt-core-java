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
import org.jruby.Ruby;
import org.jruby.RubyBignum;
import org.jruby.RubyFixnum;
import org.jruby.RubyNumeric;
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
            if (value.length != 1)
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
            return runtime.getNil();
        }
    };
    
    private static final Asn1Codec OBJECT_ID = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    };
    
    private static final Asn1Codec ENUMERATED = INTEGER;
    
    private static final Asn1Codec UTF8_STRING = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    };
    
    private static final Asn1Codec UTC_TIME = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    };
    
    private static final Asn1Codec GENERALIZED_TIME = new Asn1Codec() {

        @Override
        public byte[] encode(Ruby runtime, IRubyObject value) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public IRubyObject decode(Ruby runtime, byte[] value) {
            throw new UnsupportedOperationException("Not supported yet.");
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
}
