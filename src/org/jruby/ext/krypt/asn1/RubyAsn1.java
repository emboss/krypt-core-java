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
import impl.krypt.asn1.Header;
import impl.krypt.asn1.Length;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.ParserFactory;
import impl.krypt.asn1.Tag;
import impl.krypt.asn1.TagClass;
import impl.krypt.asn1.parser.CachingInputStream;
import impl.krypt.asn1.pem.PemInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyEnumerable;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
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
import org.jruby.runtime.BlockCallback;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.builtin.InstanceVariables;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class RubyAsn1 {
    
    private RubyAsn1() {}
    
    static final impl.krypt.asn1.Parser PARSER = new ParserFactory().newHeaderParser();
    
    public static interface Asn1Codec {
        public byte[] encode(EncodeContext ctx);
        public IRubyObject decode(DecodeContext ctx);
        public void validate(ValidateContext ctx);
    }
    
    public static final class EncodeContext {
        private final IRubyObject recv;
        private final Ruby runtime;
        private final IRubyObject value;

        public EncodeContext(IRubyObject recv, Ruby runtime, IRubyObject value) {
            this.recv = recv;
            this.runtime = runtime;
            this.value = value;
        }

        public IRubyObject getReceiver() { return recv; }
        public Ruby getRuntime() { return runtime; }
        public IRubyObject getValue() { return value; }
    }
    
    public static final class DecodeContext {
        private final IRubyObject recv;
        private final Ruby runtime;
        private final byte[] value;

        public DecodeContext(IRubyObject recv, Ruby runtime, byte[] value) {
            this.recv = recv;
            this.runtime = runtime;
            this.value = value;
        }

        public IRubyObject getReceiver() { return recv; }
        public Ruby getRuntime() { return runtime; }
        public byte[] getValue() { return value; }
    }
    
    public static final class ValidateContext {
        private final IRubyObject recv;
        private final Ruby runtime;
        private final IRubyObject value;

        public ValidateContext(IRubyObject recv, Ruby runtime, IRubyObject value) {
            this.recv = recv;
            this.runtime = runtime;
            this.value = value;
        }

        public IRubyObject getRecv() { return recv; }
        public Ruby getRuntime() { return runtime; }
        public IRubyObject getValue() { return value; }
    }
    
    public static int compareSetOfOrder(Ruby runtime, byte[] b1, byte[] b2) {
        Header h1 = PARSER.next(new ByteArrayInputStream(b1));
        Header h2 = PARSER.next(new ByteArrayInputStream(b2));
        if (h1 == null || h2 == null) throw Errors.newASN1Error(runtime, "Error while comparing values");

        Tag tag1 = h1.getTag();
        Tag tag2 = h2.getTag();
        int t1 = tag1.getTag();
        int t2 = tag2.getTag();
        if (t1 == Asn1Tags.END_OF_CONTENTS && tag1.getTagClass().equals(TagClass.UNIVERSAL))
            return 1;
        if (t2 == Asn1Tags.END_OF_CONTENTS && tag2.getTagClass().equals(TagClass.UNIVERSAL))
            return -1;
        if (t1 < t2)
            return -1;
        if (t1 > t2)
            return 1;

        int l1 = b1.length, l2 = b2.length, min = l1 < l2 ? l1 : l2;

        for (int i=0; i < min; ++i) {
            if (b1[i] != b2[i]) {
                return (b1[i] & 0xff) < (b2[i] & 0xff) ? -1 : 1; 
            }
        }

        if (l1 == l2) return 0;
        return l1 < l2 ? -1 : 1;
    }
    
    static Asn1Codec codecFor(int tag, TagClass tagClass)
    {
        Asn1Codec codec = null;
        
        if (tag < 30 && tagClass.equals(TagClass.UNIVERSAL))
            codec = Asn1Codecs.CODECS[tag];
        if (codec == null)
            codec = Asn1Codecs.DEFAULT;
        
        return codec;
    }
    
    static void initInternal(Ruby rt,
                             Asn1Data data,
                             int tag,
                             TagClass tagClass,
                             boolean isConstructed,
                             boolean isInfinite)
    {
        if (tagClass.equals(TagClass.UNIVERSAL) && tag > 30)
            throw Errors.newASN1Error(rt, "Universal tags must be <= 30");
        EncodableHeader h = new EncodableHeader(tag, tagClass, isConstructed, isInfinite);
        data.object = new Asn1Object(h, null);
        if (!isConstructed)
            data.codec = codecFor(tag, tagClass);
    }
    
    private static void checkTagAndClass(Ruby runtime, IRubyObject tag, IRubyObject tag_class) {
        if(!(tag_class instanceof RubySymbol))
            throw Errors.newASN1Error(runtime, "Tag Class must be a symbol");
        if (!(tag instanceof RubyFixnum))
            throw Errors.newASN1Error(runtime, "Tag must be a Number");
    }
    
    private static TagClass tagClassOf(Ruby runtime, IRubyObject tag_class) {
        try {
            return TagClass.forName(tag_class.toString());
        } catch (IllegalArgumentException ex) {
            throw Errors.newASN1Error(runtime, "Unknown tag class: " + tag_class.toString());
        }
    }
    
    static void defaultInitialize(Ruby runtime,
                                  Asn1Data data,
                                  IRubyObject value, 
                                  IRubyObject tag, 
                                  IRubyObject tag_class) {
        checkTagAndClass(runtime, tag, tag_class);
        
        int itag = RubyNumeric.fix2int(tag);
        TagClass tc = tagClassOf(runtime, tag_class);
        if (tag_class.toString().equals("EXPLICIT"))
            data.explicit = true;
        
        initInternal(runtime,
                     data, 
                     itag, 
                     tc, 
                     value.respondsTo("each"), 
                     false);

        data.value = value;
        data.modified = true; /* new values are "modified" by default */
        
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
        private boolean explicit = false;
        private boolean modified = false;
        
        private IRubyObject value = null;
        
        static Asn1Data newAsn1Data(Ruby runtime, Asn1Object object) {
            Tag t = object.getHeader().getTag();
            int itag = t.getTag();
            TagClass tc = t.getTagClass();
            RubyClass c = null;
            
            if (tc.equals(TagClass.UNIVERSAL) && itag > 30)
                throw Errors.newASN1Error(runtime, "Universal tag must be < 31");
            
            try {
                if (t.isConstructed()) {
                    if (itag < 31 && tc.equals(TagClass.UNIVERSAL))
                        c = (RubyClass)ASN1_INFOS[itag][1];
                    if (c == null) {
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
        
        protected boolean isModified() {
            return modified;
        }
        
        protected void setModified(boolean modified) {
            this.modified = modified;
        }
        
        protected void setCodec(Asn1Codec codec) {
            this.codec = codec;
        }
        
        protected boolean isDecoded() {
            return this.value != null;
        }
        
        protected int getDefaultTag() {
            return -1; /* to be implemented properly by UNIVERSAL classes */
        }
        
        protected Asn1Data(Ruby runtime, 
                         RubyClass type, 
                         Asn1Object object) {
            super(runtime, type);
            if (object == null) throw new NullPointerException();
            this.object = object;
            Header h = object.getHeader();
            Tag t = h.getTag();
            int itag = t.getTag();
            TagClass tc = t.getTagClass();
            Length length = h.getLength(); 
            if (!t.isConstructed())
                this.codec = codecFor(itag, tc);
            
            InstanceVariables ivs = getInstanceVariables();
            ivs.setInstanceVariable("tag", runtime.newFixnum(itag));
            ivs.setInstanceVariable("tag_class", RubyHeader.tagClassFor(runtime, tc));
            ivs.setInstanceVariable("infinite_length", runtime.newBoolean(length.isInfiniteLength()));
        }
        
        @JRubyMethod
        public IRubyObject initialize(ThreadContext ctx, IRubyObject value, IRubyObject tag, IRubyObject tag_class) {
            Ruby runtime = ctx.getRuntime();
            checkTagAndClass(runtime, tag, tag_class);
            if (tag_class.toString().equals("EXPLICIT"))
                throw Errors.newASN1Error(runtime, "Explicit tagging is only supported for explicit UNIVERSAL sub classes of ASN1Data");
            int itag = RubyNumeric.fix2int(tag);
            TagClass tc = tagClassOf(runtime, tag_class);
            boolean isConstructed = value.respondsTo("each");

            initInternal(runtime,
                         this, 
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
        
            this.modified = true; /* created from scratch means modified by default */
            
            return this;
        }
        
        protected void updateCallback() {
            Tag t = object.getHeader().getTag();
            if (!t.isConstructed())
                codec = codecFor(t.getTag(), t.getTagClass());
        }
        
        @JRubyMethod
        public IRubyObject tag() {
            return getInstanceVariables().getInstanceVariable("tag");
        }
        
        @JRubyMethod
        public IRubyObject tag_class() {
            return getInstanceVariables().getInstanceVariable("tag_class");
        }
        
        @JRubyMethod
        public IRubyObject infinite_length() {
            return getInstanceVariables().getInstanceVariable("infinite_length");
        }
        
        @JRubyMethod
        public synchronized IRubyObject value(ThreadContext ctx) {
            if (!isDecoded()) {
                decodeValue(ctx);
            }
            return value;
        }
        
        @JRubyMethod(name={"tag="})
        public IRubyObject set_tag(IRubyObject value) {
            InstanceVariables ivs = getInstanceVariables();
            IRubyObject tag = ivs.getInstanceVariable("tag");
            if (tag == value)
                return value;
            int itag = RubyNumeric.fix2int(value);
            Tag t = object.getHeader().getTag();
            t.setTag(itag);
            updateCallback();
            ivs.setInstanceVariable("tag", value);
            this.modified = true;
            return value;
        }
        
        @JRubyMethod(name={"tag_class="})
        public IRubyObject set_tag_class(ThreadContext ctx, IRubyObject value) {
            InstanceVariables ivs = getInstanceVariables();
            IRubyObject tagClass = ivs.getInstanceVariable("tag_class");
            if (tagClass == value)
                return value;
            if(!(value instanceof RubySymbol))
                throw Errors.newASN1Error(ctx.getRuntime(), "tag_class must be a symbol");
            String newTc = value.toString();
            if (getDefaultTag() == -1 && newTc.equals("EXPLICIT"))
                throw Errors.newASN1Error(ctx.getRuntime(), "Cannot explicitly tag value with unknown default tag");
            TagClass tc = TagClass.forName(newTc);
            Tag t = object.getHeader().getTag();
            t.setTagClass(tc);
            updateCallback();
            handleExplicitTagging(ctx, newTc);
            ivs.setInstanceVariable("tag_class", value);
            this.modified = true;
            return value;
        }
        
        @JRubyMethod(name={"infinite_length="})
        public IRubyObject set_infinite_length(ThreadContext ctx, IRubyObject value) {
            InstanceVariables ivs = getInstanceVariables();
            IRubyObject inflen = ivs.getInstanceVariable("infinite_length");
            if (inflen == value)
                return value;
            boolean boolVal = value.isTrue() || !value.isNil();
            Length l = object.getHeader().getLength();
            l.setInfiniteLength(boolVal);
            ivs.setInstanceVariable("infinite_length", RubyBoolean.newBoolean(ctx.getRuntime(), boolVal));
            this.modified = true;
            return value;
        }
        
        @JRubyMethod(name={"value="})
        public IRubyObject set_value(ThreadContext ctx, IRubyObject value) {
            object.getHeader().getLength().invalidateEncoding();
            object.invalidateValue();
            boolean isConstructed = value.respondsTo("each");
            object.getHeader().getTag().setConstructed(isConstructed);
            this.value = value;
            updateCallback();
            getInstanceVariables().setInstanceVariable("value", value);
            this.modified = true;
            return value;
        }
        
        @JRubyMethod
        public IRubyObject encode_to(ThreadContext ctx, IRubyObject io) {
            try {
                Ruby rt = ctx.getRuntime();
                OutputStream out = Streams.tryWrapAsOuputStream(rt, io);
                encodeToInternal(ctx, out);
                return this;
            } catch (Exception e) {
                throw Errors.newASN1Error(ctx.getRuntime(), e.getMessage());
            }
        }
        
        @JRubyMethod
        public IRubyObject to_der(ThreadContext ctx) {
            Ruby rt = ctx.getRuntime();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            encodeToInternal(ctx, baos);
            return rt.newString(new ByteList(baos.toByteArray(), false));
        }
        
        @JRubyMethod(name={"<=>"})
        public IRubyObject compare(ThreadContext ctx, IRubyObject other) {
            Ruby runtime = ctx.getRuntime();
            if (!other.respondsTo("to_der")) return runtime.getNil();
            return RubyNumeric.int2fix(runtime, 
                                       compareSetOfOrder(runtime, 
                                                         to_der(ctx).asString().getBytes(), 
                                                         Streams.toDer(other).asString().getBytes()));
        }
        
        private void handleExplicitTagging(ThreadContext ctx, String newTc) {
            boolean oldIsExplicit = explicit;
            boolean newIsExplicit = newTc.equals("EXPLICIT");
            boolean invalidate = false;
            
            if (newIsExplicit && !oldIsExplicit) {
                explicit = true;
                invalidate = true;
            }
            if (!newIsExplicit && oldIsExplicit) {
                explicit = false;
                invalidate = true;
            }
            
            if (invalidate) {
                if (!isDecoded()) {
                    decodeValue(ctx);
                }
                object.invalidateValue();
                Header h = object.getHeader();
                h.getTag().invalidateEncoding();
                h.getLength().invalidateEncoding();
            }
        }
        
        final void encodeToInternal(ThreadContext ctx, OutputStream out) {
            try {
                if (object.getValue() == null) {
                    if (explicit) {
                        value = makeExplicit(ctx);
                        object.getHeader().getTag().setConstructed(true);
                    }
                    encodeTo(ctx, value, out);
                }
                else {
                    object.encodeTo(out);
                }
                this.modified = false; /* once encoded, modified status is reset */
            } catch (IOException ex) {
                throw Errors.newSerializeError(ctx.getRuntime(), ex.getMessage());
            }
        }
        
        private IRubyObject makeExplicit(ThreadContext ctx) {
            try {
                Ruby rt = ctx.getRuntime();
                int defaultTag = getDefaultTag();
                if (defaultTag == -1)
                    throw Errors.newASN1Error(rt, "Cannot encode value with explicit tagging");
                RubyClass c = (RubyClass)ASN1_INFOS[defaultTag][1];
                if (c == null)
                    throw Errors.newASN1Error(rt, "Tag not supported " + defaultTag);
                Asn1Data universal = (Asn1Data)c.newInstance(ctx, value, Block.NULL_BLOCK);
                return RubyArray.newArray(rt, universal);
            } catch (Exception ex) {
                throw Errors.newASN1Error(ctx.getRuntime(), ex.getMessage());
            }
        }
        
        protected final void decodeValue(ThreadContext ctx) {
            if (object.getHeader().getTag().isConstructed()) {
                this.value = Asn1Constructive.decodeValue(ctx, object.getValue(), object.getHeader().getLength().isInfiniteLength());
                /* discard the cached encoding */
                object.invalidateValue();
            } else {
                this.value = Asn1Primitive.decodeValue(codec, new DecodeContext(this, ctx.getRuntime(), object.getValue()));
            }
        }
        
        private void encodeTo(ThreadContext ctx, IRubyObject value, OutputStream out) {
            try {
                if (object.getHeader().getTag().isConstructed())
                    Asn1Constructive.encodeTo(ctx, this, value, out);
                else
                    Asn1Primitive.encodeTo(codec, object, new EncodeContext(this, ctx.getRuntime(), value), out);
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
        protected void updateCallback() {
            // do nothing
        }
        
        static IRubyObject decodeValue(Asn1Codec codec, DecodeContext ctx) {
            if (codec != null)
                return codec.decode(ctx);
            else
                return Asn1Codecs.DEFAULT.decode(ctx);
        }
        
        static void encodeTo(Asn1Codec codec, 
                             Asn1Object object, 
                             EncodeContext ctx, 
                             OutputStream out) throws IOException {
            Tag t = object.getHeader().getTag();
            int itag = t.getTag();
            
            if (t.getTagClass().equals(TagClass.UNIVERSAL) && (itag == Asn1Tags.SEQUENCE || itag == Asn1Tags.SET))
                throw Errors.newASN1Error(ctx.getRuntime(), "Sequence/Set values must be constructed");
            
            byte[] encoded;
            codec.validate(new ValidateContext(ctx.getReceiver(), ctx.getRuntime(), ctx.getValue()));
            encoded = codec.encode(ctx);
            object.getHeader().getLength().setLength(encoded == null ? 0 : encoded.length);
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
        protected void updateCallback() {
            // do nothing
        }
        
        @Override
        @JRubyMethod(name={"value="})
        public IRubyObject set_value(ThreadContext ctx, IRubyObject value) {
            if (!value.respondsTo("each"))
                throw ctx.getRuntime().newArgumentError(("Value for Asn1Constructive must respond to each"));
            return super.set_value(ctx, value);
        }
        
        @JRubyMethod(frame=true)
        public IRubyObject each(ThreadContext ctx, final Block block) {
            if (!block.isGiven()) {
                return value(ctx).callMethod(ctx, "each");
            }
            return RubyEnumerable.callEach19(ctx.getRuntime(), ctx, value(ctx), new BlockCallback() {
                @Override
                public IRubyObject call(ThreadContext tc, IRubyObject[] iros, Block blk) {
                    block.yield(tc, iros[0]);
                    return tc.getRuntime().getNil();
                }
            });
        }
        
        static IRubyObject decodeValue(ThreadContext ctx, byte[] value, boolean infinite) {
            Ruby rt = ctx.getRuntime();
            if (value == null)
                return rt.newArray();
            InputStream in = new ByteArrayInputStream(value);
            List<IRubyObject> list = new ArrayList<IRubyObject>();
            ParsedHeader h;
            
            while ((h = RubyAsn1.PARSER.next(in)) != null) {
                list.add(Asn1Data.newAsn1Data(rt, h.getObject()));
            }
            
            if (infinite) {
                /* must be EOC, other ChunkedInputStream would have thrown EOF */
                list.remove(list.size() - 1);
            }
            
            return rt.newArray(list);
        }
        
        private static void validateConstructed(Ruby runtime, Header h, IRubyObject ary) {
            if (!ary.respondsTo("each"))
                throw Errors.newASN1Error(runtime, "Value for constructed type must respond to each");
            
            Tag t = h.getTag();
            int itag = t.getTag();
            
            if (t.getTagClass().equals(TagClass.UNIVERSAL)) {
                if (itag != Asn1Tags.SEQUENCE && itag != Asn1Tags.SET && 
                    !h.getLength().isInfiniteLength()) {
                 throw Errors.newASN1Error(runtime, "Primitive constructed values must be infinite length");
                }
            }
        }
        
        static void encodeTo(ThreadContext ctx, Asn1Data data, IRubyObject ary, OutputStream out) throws IOException {
            Header h = data.getObject().getHeader();
            validateConstructed(ctx.getRuntime(), h, ary);
            
            Length l = h.getLength();
            /* If the length encoding has been cached or if we have an infinite
             * length encoding, we don't need to precompute the length and may
             * start encoding right away */
            if (!l.hasBeenComputed() && !l.isInfiniteLength()) {
                /* compute the encoding of the sub elements and update length in header */
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                encodeSubElements(ctx, ary, data, baos);
                byte[] subEncoding = baos.toByteArray();
                l.setLength(subEncoding.length);
                h.encodeTo(out);
                out.write(subEncoding);
            } else {
                data.getObject().getHeader().encodeTo(out);
                encodeSubElements(ctx, ary, data, out);
            }
        }
        
        private static void encodeSubElements(ThreadContext ctx, 
                                              IRubyObject enumerable, 
                                              Asn1Data data, 
                                              final OutputStream out) {
            Asn1Object object = data.getObject();
            Tag t = object.getHeader().getTag();
            if (t.getTag() == Asn1Tags.SET &&
                t.getTagClass().equals(TagClass.UNIVERSAL) &&
                data.isModified()) {
                enumerable = sortSetValue(ctx, enumerable);
            }
            boolean infinite = object.getHeader().getLength().isInfiniteLength();
            
            if (enumerable instanceof RubyArray)
                encodeArray((RubyArray)enumerable, infinite, ctx, out);
            else
                encodeEnumerable(enumerable, infinite, ctx, out);
        }
        
        private static void encodeArray(RubyArray ary,
                                        boolean infinite,
                                        ThreadContext ctx,
                                        OutputStream out) {
            IRubyObject[] values = ary.toJavaArray();
            for (IRubyObject value : values) {
                encodeSingleSubElement(ctx, value, out);
            }
            
            if (infinite) { /* add closing EOC if it was missing */
                Asn1Data last = (Asn1Data) values[values.length - 1];
                Tag tag = last.getObject().getHeader().getTag();
                if (tag.getTag() != Asn1Tags.END_OF_CONTENTS  || !tag.getTagClass().equals(TagClass.UNIVERSAL)) {
                    encodeSingleSubElement(ctx, Asn1EndOfContents.newInstance(ctx, cASN1EndOfContents), out);
                }
            }
        }
        
        private static void encodeEnumerable(IRubyObject enumerable, 
                                             boolean infinite, 
                                             ThreadContext ctx, 
                                             final OutputStream out) {
            if (infinite)
                encodeInfiniteEnumerable(enumerable, ctx, out);
            else
                encodeDefiniteEnumerable(enumerable, ctx, out);
        }
        
        private static void encodeDefiniteEnumerable(IRubyObject enumerable, ThreadContext ctx, final OutputStream out) {
            RubyEnumerable.callEach(ctx.getRuntime(), ctx, enumerable, new BlockCallback() {
                @Override
                public IRubyObject call(ThreadContext tc, IRubyObject[] iros, Block blk) {
                    IRubyObject sub = iros[0];
                    encodeSingleSubElement(tc, sub, out);
                    return tc.getRuntime().getNil();
                }
            });
        }
        
        private static void encodeInfiniteEnumerable(IRubyObject enumerable, ThreadContext ctx, final OutputStream out) {
            class CheckEocCallback implements BlockCallback {
                private boolean lastIsEoc;

                @Override
                public IRubyObject call(ThreadContext tc, IRubyObject[] iros, Block block) {
                    IRubyObject sub = iros[0];
                    encodeSingleSubElement(tc, sub, out);
                    Asn1Data last = (Asn1Data) sub;
                    Tag tag = last.getObject().getHeader().getTag();
                    if (tag.getTag() == Asn1Tags.END_OF_CONTENTS  && tag.getTagClass().equals(TagClass.UNIVERSAL)) {
                        lastIsEoc = true;
                    } else {
                        lastIsEoc = false;
                    }
                    
                    return tc.getRuntime().getNil();
                }
                
                public boolean lastIsEoc() { return lastIsEoc; }
            }
            Ruby runtime = ctx.getRuntime();
            CheckEocCallback cb = new CheckEocCallback();
            RubyEnumerable.callEach(runtime, ctx, enumerable, cb);
            if (!cb.lastIsEoc()) { /* add a closing EOC if it was missing */
                encodeSingleSubElement(ctx, Asn1EndOfContents.newInstance(ctx, cASN1EndOfContents), out);
            }
        }
        
        private static void encodeSingleSubElement(ThreadContext ctx, IRubyObject value, OutputStream out) {
            if (!(value instanceof Asn1Data))
                throw Errors.newError(ctx.getRuntime(), "ArgumentError", "Value is not an ASN1Data");
            ((Asn1Data)value).encodeToInternal(ctx, out);
        }
        
        private static IRubyObject sortSetValue(ThreadContext ctx, IRubyObject enumerable) {
            if (enumerable.respondsTo("sort!")) {
                enumerable.callMethod(ctx, "sort!");
                return enumerable;
            }
            if (enumerable.respondsTo("sort")) {
                return enumerable.callMethod(ctx, "sort");
            }
            return fallbackSortSetValue(ctx, enumerable);
        }
        
        private static IRubyObject fallbackSortSetValue(ThreadContext ctx, IRubyObject enumerable) {
            final RubyArray tmp = RubyArray.newArray(ctx.getRuntime());
            RubyEnumerable.callEach19(ctx.getRuntime(), ctx, enumerable, new BlockCallback() {
                @Override
                public IRubyObject call(ThreadContext tc, IRubyObject[] iros, Block blk) {
                    tmp.add(iros[0]);
                    return tc.getRuntime().getNil();
                }
            });
            tmp.callMethod(ctx, "sort!");
            return tmp;
        }
    }
    
    @JRubyMethod(meta = true)
    public static IRubyObject decode_der(ThreadContext ctx, IRubyObject recv, IRubyObject value) {
        try {
            Ruby rt = ctx.getRuntime();
            InputStream in = Streams.asInputStreamDer(rt, value);
            IRubyObject ret = generateAsn1Data(rt, in);
            if (ret == null) throw Errors.newASN1Error(ctx.getRuntime(), "Could not decode ASN.1 data");
            return ret;
        } catch(Exception e) {
            throw Errors.newParseError(ctx.getRuntime(), e.getMessage());
        }
    }
    
    @JRubyMethod(meta = true)
    public static IRubyObject decode_pem(ThreadContext ctx, IRubyObject recv, IRubyObject value) {
        try {
            Ruby rt = ctx.getRuntime();
            InputStream in = new PemInputStream(Streams.asInputStreamPem(rt, value));
            IRubyObject ret = generateAsn1Data(rt, in);
            if (ret == null) throw Errors.newASN1Error(ctx.getRuntime(), "Could not decode ASN.1 data");
            return ret;
        } catch(Exception e) {
            throw Errors.newParseError(ctx.getRuntime(), e.getMessage());
        }
    }
    
    @JRubyMethod(meta = true)
    public static IRubyObject decode(ThreadContext ctx, IRubyObject recv, IRubyObject value) {
        IRubyObject ret;
        try {
            Ruby rt = ctx.getRuntime();
            InputStream in = Streams.asInputStreamDer(rt, value);
            CachingInputStream cache = new CachingInputStream(in);
            try {
                InputStream pem = new PemInputStream(cache);
                if ((ret = generateAsn1Data(rt, pem)) != null) return ret;
            } catch (RaiseException ex) { }
            InputStream prefix = new ByteArrayInputStream(cache.getCachedBytes());
            InputStream retry = new SequenceInputStream(prefix, in);
            ret = generateAsn1Data(rt, retry);    
        } catch(Exception e) {
            throw Errors.newASN1Error(ctx.getRuntime(), e.getMessage());
        }
        if (ret == null) throw Errors.newASN1Error(ctx.getRuntime(), "Could not decode ASN.1 data");
        return ret;
    }
    
    protected static IRubyObject generateAsn1Data(Ruby runtime, InputStream in) {
        ParsedHeader h = PARSER.next(in);
        if (h == null)
            return null;
        return Asn1Data.newAsn1Data(runtime, h.getObject());
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

        mASN1.defineAnnotatedMethods(RubyAsn1.class);
        
        cASN1Data = mASN1.defineClassUnder("ASN1Data", runtime.getObject(), Asn1Data.ALLOCATOR);
        cASN1Data.includeModule(runtime.getModule("Comparable"));
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
        for(int i=0; i<ASN1_INFOS.length; i++) {
            if((((String)ASN1_INFOS[i][0])).charAt(0) != '[') {
                ary.add(runtime.newString(((String)(ASN1_INFOS[i][0]))));
                mASN1.defineConstant(((String)(ASN1_INFOS[i][0])), runtime.newFixnum(i));
            } 
            else {
                ary.add(runtime.getNil());
            }
        }
        mASN1.setConstant("UNIVERSAL_TAG_NAME",runtime.newArray(ary));
        
        /* Header must be created before Parser, since Parser references the Header class */
        RubyHeader.createHeader(runtime, mASN1);
        RubyParser.createParser(runtime, mASN1);
        RubyTemplate.createTemplate(runtime, mASN1);
    }    
}
