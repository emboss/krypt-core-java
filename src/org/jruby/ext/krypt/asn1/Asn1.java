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

import impl.krypt.asn1.Asn1Object;
import impl.krypt.asn1.EncodableHeader;
import impl.krypt.asn1.Length;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.ParserFactory;
import impl.krypt.asn1.Tag;
import impl.krypt.asn1.TagClass;
import impl.krypt.asn1.Tags;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.Streams;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1BitString;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1BmpString;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Boolean;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1EndOfContents;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Enumerated;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1GeneralString;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1GeneralizedTime;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1GraphicString;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Ia5String;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Integer;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Iso64String;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Null;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1NumericString;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1ObjectId;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1OctetString;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1PrintableString;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Sequence;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Set;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1T61String;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1UniversalString;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1UtcTime;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1Utf8String;
import org.jruby.ext.krypt.asn1.Asn1DataClasses.Asn1VideotexString;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.builtin.InstanceVariables;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Asn1 {
    
    private Asn1() {}
    
    static final impl.krypt.asn1.Parser PARSER = new ParserFactory().newHeaderParser();
    
    public static interface Asn1Codec {
        public byte[] encode(Ruby runtime, IRubyObject value);
        public IRubyObject decode(Ruby runtime, byte[] value);
    }
    
    private static Asn1Codec codecFor(int tag, TagClass tagClass)
    {
        Asn1Codec codec;
        if (tag < 30 && tagClass.equals(TagClass.UNIVERSAL))
            codec = Asn1Codecs.CODECS[tag];
        else
            codec = null;
        return codec;
    }
    
    static void initInternal(Asn1Data data,
                              int tag,
                              TagClass tagClass,
                              boolean isConstructed,
                              boolean isInfinite)
    {
        EncodableHeader h = new EncodableHeader(tag, tagClass, isConstructed, isInfinite);
        data.object = new Asn1Object(h, null);
        data.codec = codecFor(tag, tagClass);
    }
    
    static void defaultInitialize(Asn1Data data,
                                          Ruby runtime, 
                                          IRubyObject value, 
                                          IRubyObject tag, 
                                          IRubyObject tag_class, 
                                          boolean isConstructed) {
        if(!(tag_class instanceof RubySymbol)) {
            throw Errors.newASN1Error(runtime, "tag_class must be a symbol");
        }
        int itag = RubyNumeric.fix2int(tag);
        TagClass tc = TagClass.valueOf(tag_class.toString());
        
        initInternal(data, 
                    itag, 
                    tc, 
                    isConstructed, 
                    false);

        data.value = value;
        
        InstanceVariables ivs = data.getInstanceVariables();
        ivs.setInstanceVariable("tag", tag);
        ivs.setInstanceVariable("tag_class", tag_class);
        ivs.setInstanceVariable("value", value);
        ivs.setInstanceVariable("infinite_length", runtime.getFalse());
    }
    
    public static class Asn1Data extends RubyObject {
        
        private static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Asn1Data(runtime, type);
            }
        };
        
        protected Asn1Data(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }
        
        private Asn1Object object;
        private Asn1Codec codec;
        
        private IRubyObject value = null;
        
        static Asn1Data newAsn1Data(Ruby runtime, Asn1Object object) {
            Tag t = object.getHeader().getTag();
            int itag = t.getTag();
            TagClass tc = t.getTagClass();
            RubyClass c = null;
            
            try {
                if (t.isConstructed()) {
                    if (itag < 31 && tc.equals(TagClass.UNIVERSAL))
                        c = (RubyClass)ASN1_INFOS[itag][1];
                    if (c == null || object.getHeader().getLength().isInfiniteLength()) {
                        c = cASN1Constructive;
                        return new Asn1Constructive(runtime, c, object);
                    } else {
                        return (Asn1Data)((Constructor)ASN1_INFOS[itag][2]).newInstance(runtime, c, object);
                    }
                }
                else {
                    if (itag < 31 && tc.equals(TagClass.UNIVERSAL)) {
                        c = (RubyClass)ASN1_INFOS[itag][1];
                        if (c == null) {
                            c = cASN1Primitive;
                            return new Asn1Primitive(runtime, c, object);
                        } else {
                            return (Asn1Data)((Constructor)ASN1_INFOS[itag][2]).newInstance(runtime, c, object);
                        }
                    } else {
                        return new Asn1Data(runtime,
                                            cASN1Data,
                                            object);
                    }
                }
            } catch (Exception ex) {
                throw runtime.newRuntimeError(ex.getMessage());
            }
        }
        
        protected Asn1Object getObject() {
            return object;
        }
        
        protected Asn1Codec getCodec() {
            return codec;
        }
        
        protected Asn1Data(Ruby runtime, 
                         RubyClass type, 
                         Asn1Object object) {
            super(runtime, type);
            if (object == null) throw new NullPointerException();
            this.object = object;
            impl.krypt.asn1.Header h = object.getHeader();
            Tag t = h.getTag();
            int itag = t.getTag();
            TagClass tc = t.getTagClass();
            Length length = h.getLength(); 
            this.codec = codecFor(itag, tc);
            
            InstanceVariables ivs = getInstanceVariables();
            ivs.setInstanceVariable("tag", runtime.newFixnum(itag));
            ivs.setInstanceVariable("tag_class", Header.tagClassFor(runtime, tc));
            ivs.setInstanceVariable("infinite_length", runtime.newBoolean(length.isInfiniteLength()));
        }
        
        @JRubyMethod
        public IRubyObject initialize(ThreadContext ctx, IRubyObject value, IRubyObject tag, IRubyObject tag_class) {
            Ruby runtime = ctx.getRuntime();
            if(!(tag_class instanceof RubySymbol)) {
                throw Errors.newASN1Error(runtime, "tag_class must be a symbol");
            }
            int itag = RubyNumeric.fix2int(tag);
            TagClass tc = TagClass.valueOf(tag_class.toString());
            boolean isConstructed = value instanceof RubyArray;

            initInternal(this, 
                        itag, 
                        tc, 
                        isConstructed, 
                        false);
            
            this.value = value;
            
            InstanceVariables ivs = getInstanceVariables();
            ivs.setInstanceVariable("tag", tag);
            ivs.setInstanceVariable("tag_class", tag_class);
            ivs.setInstanceVariable("value", value);
            ivs.setInstanceVariable("infinite_length", runtime.getFalse());
        
            return this;
        }
        
        @JRubyMethod
        public synchronized IRubyObject tag() {
            return getInstanceVariables().getInstanceVariable("tag");
        }
        
        @JRubyMethod
        public synchronized IRubyObject tag_class() {
            return getInstanceVariables().getInstanceVariable("tag_class");
        }
        
        @JRubyMethod
        public synchronized IRubyObject infinite_length() {
            return getInstanceVariables().getInstanceVariable("infinite_length");
        }
        
        @JRubyMethod
        public synchronized IRubyObject value(ThreadContext ctx) {
            if (value == null) {
                value = decodeValue(ctx);
            }
            return value;
        }
        
        @JRubyMethod(name={"tag="})
        public synchronized IRubyObject set_tag(IRubyObject value) {
            InstanceVariables ivs = getInstanceVariables();
            IRubyObject tag = ivs.getInstanceVariable("tag");
            if (tag == value)
                return value;
            int itag = RubyNumeric.fix2int(value);
            Tag t = object.getHeader().getTag();
            t.setTag(itag);
            codec = codecFor(itag, t.getTagClass());
            ivs.setInstanceVariable("tag", value);
            return value;
        }
        
        @JRubyMethod(name={"tag_class="})
        public synchronized IRubyObject set_tag_class(ThreadContext ctx, IRubyObject value) {
            InstanceVariables ivs = getInstanceVariables();
            IRubyObject tagClass = ivs.getInstanceVariable("tag_class");
            if (tagClass == value)
                return value;
            if(!(value instanceof RubySymbol))
                throw Errors.newASN1Error(ctx.getRuntime(), "tag_class must be a symbol");
            TagClass tc = TagClass.valueOf(value.toString());
            Tag t = object.getHeader().getTag();
            t.setTagClass(tc);
            codec = codecFor(t.getTag(), tc);
            ivs.setInstanceVariable("tag_class", value);
            return value;
        }
        
        @JRubyMethod(name={"infinite_length="})
        public synchronized IRubyObject set_infinite_length(IRubyObject value) {
            InstanceVariables ivs = getInstanceVariables();
            IRubyObject inflen = ivs.getInstanceVariable("infinite_length");
            if (inflen == value)
                return value;
            boolean boolVal = value.isTrue();
            Length l = object.getHeader().getLength();
            l.setInfiniteLength(boolVal);
            ivs.setInstanceVariable("infinite_length", value);
            return value;
        }
        
        @JRubyMethod(name={"value="})
        public synchronized IRubyObject set_value(ThreadContext ctx, IRubyObject value) {
            object.getHeader().getLength().setLength(0);
            object.invalidateValue();
            boolean isConstructed = value instanceof RubyArray;
            object.getHeader().getTag().setConstructed(isConstructed);
            this.value = value;
            getInstanceVariables().setInstanceVariable("value", value);
            return value;
        }
        
        @JRubyMethod
        public synchronized IRubyObject encode_to(ThreadContext ctx, IRubyObject io) {
            Ruby rt = ctx.getRuntime();
            OutputStream out = Streams.tryWrapAsOuputStream(rt, io);
            encodeToInternal(ctx, out);
            return this;
        }
        
        @JRubyMethod
        public synchronized IRubyObject to_der(ThreadContext ctx) {
            Ruby rt = ctx.getRuntime();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            encodeToInternal(ctx, baos);
            return rt.newString(new ByteList(baos.toByteArray(), false));
        }
        
        final void encodeToInternal(ThreadContext ctx, OutputStream out) {
            try {
                if (object.getValue() == null)
                    computeAndEncode(ctx, out);
                else
                    object.encodeTo(out);
            } catch (IOException ex) {
                throw Errors.newSerializeError(ctx.getRuntime(), ex.getMessage());
            }
        }
        
        private void computeAndEncode(ThreadContext ctx, OutputStream out) throws IOException {
            Tag t = object.getHeader().getTag();
            int itag = t.getTag();
            if (t.getTagClass().equals(TagClass.UNIVERSAL) &&
                (itag == Tags.NULL || itag == Tags.END_OF_CONTENTS)) {
                /* Treat NULL and END_OF_CONTENTS exceptionally. No additional
                 * encoding step needed since they have no value to encode */
                 object.encodeTo(out);
            } else {
                encodeTo(ctx, value, out);
            }
        }
        
        protected IRubyObject decodeValue(ThreadContext ctx) {
            if (object.getHeader().getTag().isConstructed()) {
                return Asn1Constructive.decodeValue(ctx, object.getValue());
            } else {
                return Asn1Primitive.decodeValue(ctx.getRuntime(), codec, object.getValue());
            }
        }
        
        protected void encodeTo(ThreadContext ctx, IRubyObject value, OutputStream out) {
            try {
                if (object.getHeader().getTag().isConstructed()) {
                    Asn1Constructive.encodeTo(ctx, object, value, out);
                } else {
                    Asn1Primitive.encodeTo(ctx.getRuntime(), codec, object, value, out);
                }
            } catch (IOException ex) {
                throw Errors.newSerializeError(ctx.getRuntime(), ex.getMessage());
            }
        }
    }
    
    public static class Asn1Primitive extends Asn1Data {
        
        static ObjectAllocator PRIMITIVE_ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Asn1Primitive(runtime, type);
            }
        };
        
        protected Asn1Primitive(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }
        
        public Asn1Primitive(Ruby runtime, RubyClass type, Asn1Object object) {
            super(runtime, type, object);
        }
        
        @Override
        protected IRubyObject decodeValue(ThreadContext ctx) {
            return decodeValue(ctx.getRuntime(), getCodec(), getObject().getValue());
        }
        
        @Override
        protected void encodeTo(ThreadContext ctx, IRubyObject value, OutputStream out) {
            try {
                encodeTo(ctx.getRuntime(), getCodec(), getObject(), value, out);
            } catch (Exception ex) {
                throw Errors.newSerializeError(ctx.getRuntime(), ex.getMessage());
            }
        }
        
        static IRubyObject decodeValue(Ruby runtime, Asn1Codec codec, byte[] value) {
            if (codec != null)
                return codec.decode(runtime, value);
            else
                return Asn1Codecs.DEFAULT.decode(runtime, value);
        }
        
        static void encodeTo(Ruby runtime, Asn1Codec codec, Asn1Object object, IRubyObject value, OutputStream out) throws IOException {
            byte[] encoded;
            if (codec != null)
                encoded = codec.encode(runtime, value);
            else
                encoded = Asn1Codecs.DEFAULT.encode(runtime, value);
            object.getHeader().getLength().setLength(encoded.length);
            object.setValue(encoded);
            object.encodeTo(out);
        }
    }
    
    public static class Asn1Constructive extends Asn1Data {
        
        static ObjectAllocator CONSTRUCTIVE_ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Asn1Constructive(runtime, type);
            }
        };
        
        protected Asn1Constructive(Ruby runtime, RubyClass type) {
            super(runtime, type);
        }
        
        public Asn1Constructive(Ruby runtime, RubyClass type, Asn1Object object) {
            super(runtime, type, object);
        }
        
        @Override
        @JRubyMethod(name={"value="})
        public IRubyObject set_value(ThreadContext ctx, IRubyObject value) {
            if (!(value instanceof RubyArray))
                throw ctx.getRuntime().newArgumentError(("Value for Asn1Constructive must be an array"));
            return super.set_value(ctx, value);
        }
        
        @JRubyMethod(frame=true)
        public IRubyObject each(ThreadContext ctx, Block block) {
            RubyArray arr = (RubyArray)value(ctx);
            for (IRubyObject obj : arr.toJavaArray()) {
                block.yield(ctx, obj);
            }
            return ctx.getRuntime().getNil();
        }
        
        @Override
        protected IRubyObject decodeValue(ThreadContext ctx) {
            return decodeValue(ctx, getObject().getValue());
        }
        
        @Override
        protected void encodeTo(ThreadContext ctx, IRubyObject value, OutputStream out) {
            try {
                encodeTo(ctx, getObject(), value, out);
            } catch (Exception ex) {
                throw Errors.newSerializeError(ctx.getRuntime(), ex.getMessage());
            }
        }
        
        static IRubyObject decodeValue(ThreadContext ctx, byte[] value) {
            Ruby rt = ctx.getRuntime();
            InputStream in = new ByteArrayInputStream(value);
            List<IRubyObject> list = new ArrayList<IRubyObject>();
            ParsedHeader h;
            
            while ((h = Asn1.PARSER.next(in)) != null) {
                list.add(Asn1Data.newAsn1Data(rt, h.getObject()));
            }
            
            return rt.newArray(list);
        }
        
        static void encodeTo(ThreadContext ctx, Asn1Object object, IRubyObject ary, OutputStream out) throws IOException {
            Length l = object.getHeader().getLength();
            if (l.getEncoding() == null) {
                /* TODO compute and update length in header */
                throw new UnsupportedOperationException("Not implemented yet");
            }
            
            object.getHeader().encodeTo(out);
            
            if (!(ary instanceof RubyArray))
                throw new IllegalArgumentException("Value is not an array");
            
            for (IRubyObject value : ((RubyArray)ary).toJavaArray()) {
                if (!(value instanceof Asn1Data))
                    throw new IllegalArgumentException("Value in array is not an Asn1Data");
                ((Asn1Data)value).encodeToInternal(ctx, out);
            }
        }
    }
    
    @JRubyMethod(meta = true)
    public static IRubyObject decode(ThreadContext ctx, IRubyObject recv, IRubyObject value) {
        try {
            Ruby rt = ctx.getRuntime();
            InputStream in;
            if (value.respondsTo("read")) {
                in = Streams.tryWrapAsInputStream(rt, value);
            } else {
                in = new ByteArrayInputStream(toDerIfPossible(value).convertToString().getBytes());
            }
            ParsedHeader h = PARSER.next(in);
            return Asn1Data.newAsn1Data(rt, h.getObject());
        } catch(Exception e) {
            throw Errors.newParseError(ctx.getRuntime(), e.getMessage());
        }
    }
    
    public static IRubyObject toDer(IRubyObject obj) {
        return obj.callMethod(obj.getRuntime().getCurrentContext(), "to_der");
    }

    public static IRubyObject toDerIfPossible(IRubyObject der) {
        if(der.respondsTo("to_der")) {
            return toDer(der);
        } else {
            return der;
        }
    }
    
    private static RubyClass cASN1Data;
    private static RubyClass cASN1Primitive;
    private static RubyClass cASN1Constructive;
    
    private static RubyClass cASN1EndOfContents;
    private static RubyClass cASN1Boolean;
    private static RubyClass cASN1Integer;
    private static RubyClass cASN1BitString;
    private static RubyClass cASN1OctetString;
    private static RubyClass cASN1Null;
    private static RubyClass cASN1ObjectId;
    private static RubyClass cASN1Enumerated;
    private static RubyClass cASN1Utf8String;
    private static RubyClass cASN1Sequence;
    private static RubyClass cASN1Set;
    private static RubyClass cASN1NumericString;
    private static RubyClass cASN1PrintableString;
    private static RubyClass cASN1T61String;
    private static RubyClass cASN1VideotexString;
    private static RubyClass cASN1Ia5String;
    private static RubyClass cASN1UtcTime;
    private static RubyClass cASN1GeneralizedTime;
    private static RubyClass cASN1GraphicString;
    private static RubyClass cASN1Iso64String;
    private static RubyClass cASN1GeneralString;
    private static RubyClass cASN1UniversalString;
    private static RubyClass cASN1BmpString;
    
    private static Object[][] ASN1_INFOS;
    
    public static void createAsn1(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyModule mASN1 = runtime.defineModuleUnder("ASN1", krypt);

        RubyClass asn1Error = mASN1.defineClassUnder("ASN1Error", kryptError, kryptError.getAllocator());
        mASN1.defineClassUnder("ParseError", asn1Error, asn1Error.getAllocator());
        mASN1.defineClassUnder("SerializeError", asn1Error, asn1Error.getAllocator());

        mASN1.defineAnnotatedMethods(Asn1.class);
        
        cASN1Data = mASN1.defineClassUnder("ASN1Data", runtime.getObject(), Asn1Data.ALLOCATOR);
        cASN1Data.defineAnnotatedMethods(Asn1Data.class);

        cASN1Primitive = mASN1.defineClassUnder("Primitive", cASN1Data, Asn1Primitive.PRIMITIVE_ALLOCATOR);
        cASN1Primitive.defineAnnotatedMethods(Asn1Primitive.class);

        cASN1Constructive = mASN1.defineClassUnder("Constructive", cASN1Data, Asn1Constructive.CONSTRUCTIVE_ALLOCATOR);
        cASN1Constructive.includeModule(runtime.getModule("Enumerable"));
        cASN1Constructive.defineAnnotatedMethods(Asn1Constructive.class);

        cASN1EndOfContents   = mASN1.defineClassUnder("EndOfContents", cASN1Primitive, Asn1EndOfContents.ALLOCATOR);
        cASN1EndOfContents.defineAnnotatedMethods(Asn1EndOfContents.class);
        cASN1Boolean         = mASN1.defineClassUnder("Boolean", cASN1Primitive, Asn1Boolean.ALLOCATOR);
        cASN1Boolean.defineAnnotatedMethods(Asn1Boolean.class);
        cASN1Integer         = mASN1.defineClassUnder("Integer", cASN1Primitive, Asn1Integer.ALLOCATOR);
        cASN1Integer.defineAnnotatedMethods(Asn1Integer.class);
        cASN1Enumerated      = mASN1.defineClassUnder("Enumerated", cASN1Primitive, Asn1Enumerated.ALLOCATOR);
        cASN1Enumerated.defineAnnotatedMethods(Asn1Enumerated.class);
        cASN1BitString       = mASN1.defineClassUnder("BitString", cASN1Primitive, Asn1BitString.ALLOCATOR);
        cASN1BitString.defineAnnotatedMethods(Asn1BitString.class);
        cASN1OctetString     = mASN1.defineClassUnder("OctetString",cASN1Primitive, Asn1OctetString.ALLOCATOR);
        cASN1OctetString.defineAnnotatedMethods(Asn1OctetString.class);
        cASN1Utf8String      = mASN1.defineClassUnder("UTF8String",cASN1Primitive, Asn1Utf8String.ALLOCATOR);
        cASN1Utf8String.defineAnnotatedMethods(Asn1Utf8String.class);
        cASN1NumericString   = mASN1.defineClassUnder("NumericString",cASN1Primitive, Asn1NumericString.ALLOCATOR);
        cASN1NumericString.defineAnnotatedMethods(Asn1NumericString.class);
        cASN1PrintableString = mASN1.defineClassUnder("PrintableString",cASN1Primitive, Asn1PrintableString.ALLOCATOR);
        cASN1PrintableString.defineAnnotatedMethods(Asn1PrintableString.class);
        cASN1T61String       = mASN1.defineClassUnder("T61String",cASN1Primitive, Asn1T61String.ALLOCATOR);
        cASN1T61String.defineAnnotatedMethods(Asn1T61String.class);
        cASN1VideotexString  = mASN1.defineClassUnder("VideotexString",cASN1Primitive, Asn1VideotexString.ALLOCATOR);
        cASN1VideotexString.defineAnnotatedMethods(Asn1VideotexString.class);
        cASN1Ia5String       = mASN1.defineClassUnder("IA5String",cASN1Primitive, Asn1Ia5String.ALLOCATOR);
        cASN1Ia5String.defineAnnotatedMethods(Asn1Ia5String.class);
        cASN1GraphicString   = mASN1.defineClassUnder("GraphicString",cASN1Primitive, Asn1GraphicString.ALLOCATOR);
        cASN1GraphicString.defineAnnotatedMethods(Asn1GraphicString.class);
        cASN1Iso64String     = mASN1.defineClassUnder("ISO64String",cASN1Primitive, Asn1Iso64String.ALLOCATOR);
        cASN1Iso64String.defineAnnotatedMethods(Asn1Iso64String.class);
        cASN1GeneralString   = mASN1.defineClassUnder("GeneralString",cASN1Primitive, Asn1GeneralString.ALLOCATOR);
        cASN1GeneralString.defineAnnotatedMethods(Asn1GeneralString.class);
        cASN1UniversalString = mASN1.defineClassUnder("UniversalString",cASN1Primitive, Asn1UniversalString.ALLOCATOR);
        cASN1UniversalString.defineAnnotatedMethods(Asn1UniversalString.class);
        cASN1BmpString       = mASN1.defineClassUnder("BMPString",cASN1Primitive, Asn1BmpString.ALLOCATOR);
        cASN1BmpString.defineAnnotatedMethods(Asn1BmpString.class);
        cASN1Null            = mASN1.defineClassUnder("Null",cASN1Primitive, Asn1Null.ALLOCATOR);
        cASN1Null.defineAnnotatedMethods(Asn1Null.class);
        cASN1ObjectId        = mASN1.defineClassUnder("ObjectId",cASN1Primitive, Asn1ObjectId.ALLOCATOR);
        cASN1ObjectId.defineAnnotatedMethods(Asn1ObjectId.class);
        cASN1UtcTime         = mASN1.defineClassUnder("UTCTime",cASN1Primitive, Asn1UtcTime.ALLOCATOR);
        cASN1UtcTime.defineAnnotatedMethods(Asn1UtcTime.class);
        cASN1GeneralizedTime = mASN1.defineClassUnder("GeneralizedTime",cASN1Primitive, Asn1GeneralizedTime.ALLOCATOR);
        cASN1GeneralizedTime.defineAnnotatedMethods(Asn1GeneralizedTime.class);
        cASN1Sequence        = mASN1.defineClassUnder("Sequence",cASN1Constructive, Asn1Sequence.ALLOCATOR);
        cASN1Sequence.defineAnnotatedMethods(Asn1Sequence.class);
        cASN1Set             = mASN1.defineClassUnder("Set",cASN1Constructive, Asn1Set.ALLOCATOR);
        cASN1Set.defineAnnotatedMethods(Asn1Set.class);

        cASN1BitString.attr_accessor(runtime.getCurrentContext(), new IRubyObject[]{runtime.newSymbol("unused_bits")});
        
        try {
            Class<?>[] params = new Class<?>[] { Ruby.class, RubyClass.class, Asn1Object.class };
            ASN1_INFOS = new Object[][] {
                { "END_OF_CONTENTS",   cASN1EndOfContents  , Asn1EndOfContents.class.getConstructor(params)   },
                { "BOOLEAN",           cASN1Boolean        , Asn1Boolean.class.getConstructor(params)         },
                { "INTEGER",           cASN1Integer        , Asn1Integer.class.getConstructor(params)         },
                { "BIT_STRING",        cASN1BitString      , Asn1BitString.class.getConstructor(params)       },
                { "OCTET_STRING",      cASN1OctetString    , Asn1OctetString.class.getConstructor(params)     },
                { "NULL",              cASN1Null           , Asn1Null.class.getConstructor(params)            },
                { "OBJECT_ID",         cASN1ObjectId       , Asn1ObjectId.class.getConstructor(params)        },
                { "OBJECT_DESCRIPTOR", null                , null                                             },
                { "EXTERNAL",          null                , null                                             },
                { "REAL",              null                , null                                             },
                { "ENUMERATED",        cASN1Enumerated     , Asn1Enumerated.class.getConstructor(params)      },
                { "EMBEDDED_PDV",      null                , null                                             },
                { "UTF8_STRING",       cASN1Utf8String     , Asn1Utf8String.class.getConstructor(params)      },
                { "RELATIVE_OID",      null                , null                                             },
                { "[UNIVERSAL 14]",    null                , null                                             },
                { "[UNIVERSAL 15]",    null                , null                                             },
                { "SEQUENCE",          cASN1Sequence       , Asn1Sequence.class.getConstructor(params)        },
                { "SET",               cASN1Set            , Asn1Set.class.getConstructor(params)             },
                { "NUMERIC_STRING",    cASN1NumericString  , Asn1NumericString.class.getConstructor(params)   },
                { "PRINTABLE_STRING",  cASN1PrintableString, Asn1PrintableString.class.getConstructor(params) },
                { "T61_STRING",        cASN1T61String      , Asn1T61String.class.getConstructor(params)       },
                { "VIDEOTEX_STRING",   cASN1VideotexString , Asn1VideotexString.class.getConstructor(params)  },
                { "IA5_STRING",        cASN1Ia5String      , Asn1Ia5String.class.getConstructor(params)       },
                { "UTC_TIME",          cASN1UtcTime        , Asn1UtcTime.class.getConstructor(params)         },
                { "GENERALIZED_TIME",  cASN1GeneralizedTime, Asn1GeneralizedTime.class.getConstructor(params) },
                { "GRAPHIC_STRING",    cASN1GraphicString  , Asn1GraphicString.class.getConstructor(params)   },
                { "ISO64_STRING",      cASN1Iso64String    , Asn1Iso64String.class.getConstructor(params)     },
                { "GENERAL_STRING",    cASN1GeneralString  , Asn1GeneralString.class.getConstructor(params)   },
                { "UNIVERSAL_STRING",  cASN1UniversalString, Asn1UniversalString.class.getConstructor(params) },
                { "CHARACTER_STRING",  null                , null                                             },
                { "BMP_STRING",        cASN1BmpString      , Asn1BmpString.class.getConstructor(params)       }
            };
        } catch (Exception ex) {
            throw runtime.newRuntimeError(ex.getMessage());
        }
        
        List<IRubyObject> ary = new ArrayList<IRubyObject>();
        mASN1.setConstant("UNIVERSAL_TAG_NAME",runtime.newArray(ary));
        for(int i=0; i<ASN1_INFOS.length; i++) {
            if((((String)ASN1_INFOS[i][0])).charAt(0) != '[') {
                ary.add(runtime.newString(((String)(ASN1_INFOS[i][0]))));
                mASN1.defineConstant(((String)(ASN1_INFOS[i][0])), runtime.newFixnum(i));
            } 
            else {
                ary.add(runtime.getNil());
            }
        }
        
        Parser.createParser(runtime, mASN1);
        Header.createHeader(runtime, mASN1);
    }    
}
