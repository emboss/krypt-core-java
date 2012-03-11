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
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.ParserFactory;
import impl.krypt.asn1.Tag;
import impl.krypt.asn1.TagClass;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.Streams;
import org.jruby.ext.krypt.asn1.RubyAsn1.Asn1Codec;
import org.jruby.ext.krypt.asn1.RubyAsn1.DecodeContext;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class RubyTemplate {
    
    static final impl.krypt.asn1.Parser PARSER = new ParserFactory().newHeaderParser();
    
    public static class RubyAsn1Template extends RubyObject {
        
        private final Asn1Template template;
        
        protected RubyAsn1Template(Ruby runtime, RubyClass type, Asn1Template template) {
            super(runtime, type);
            if (template == null) throw new NullPointerException("template");
            this.template = template;
        }
        
        public Asn1Template getTemplate() { return this.template; }
        
        @JRubyMethod
        public IRubyObject get_callback(ThreadContext ctx, IRubyObject ivname) {
            String name = ivname.asJavaString();
            return ensureParsedAndDecoded(ctx, name);
        }
        
        @JRubyMethod
        public IRubyObject set_callback(ThreadContext ctx, IRubyObject ivname, IRubyObject value) {
            setInstanceVariable(ivname.asJavaString(), value);
            template.setModified(true);
            return value;
        }
        
        private IRubyObject ensureParsedAndDecoded(ThreadContext ctx, String ivname) {
            template.parse(ctx, this);
            /* ivname has a leading @ */
            Value v = (Value) getInstanceVariable(ivname.substring(1));
            Asn1Template.decode(ctx, v);
            return v.getTemplate().getValue();
        }
    }
    
    public static class Asn1Template {
        public Asn1Template(Asn1Object object, RubyHash definition) {
            if (object == null) throw new NullPointerException("object");
            this.object = object;
            this.isParsed = false;
            this.isDecoded = false;
            this.isModified = false;
            this.definition = definition;
        }
        
        private final Asn1Object object;
        private RubyHash definition;
        private IRubyObject value;
        private boolean isParsed;
        private boolean isDecoded;
        private boolean isModified;

        public Asn1Object getObject() { return this.object; }
        public RubyHash getDefinition() { return this.definition; }
        public void setDefinition(RubyHash definition) { this.definition = definition; }
        public IRubyObject getValue() { return this.value; }
        public void setValue(IRubyObject value) { this.value = value; }
        public boolean isParsed() { return this.isParsed; }
        public void setParsed(boolean parsed) { this.isParsed = parsed; }
        public boolean isDecoded() { return this.isDecoded; }
        public void setDecoded(boolean decoded) { this.isDecoded = decoded; }
        public boolean isModified() { return this.isModified; }
        public void setModified(boolean modified) { this.isModified = true; }
        
        private <T> T accept(ThreadContext ctx, CodecVisitor<T> visitor) {
            IRubyObject codec = ((IRubyObject) definition.get(CODEC));
            T ret;
            if (codec == CODEC_PRIMITIVE) ret = visitor.visitPrimitive(ctx, this);
            else if (codec == CODEC_TEMPLATE) ret = visitor.visitTemplate(ctx, this);
            else if (codec == CODEC_SEQUENCE) ret = visitor.visitSequence(ctx, this);
            else if (codec == CODEC_SET) ret = visitor.visitSet(ctx, this);
            else if (codec == CODEC_SEQUENCE_OF) ret = visitor.visitSequenceOf(ctx, this);
            else if (codec == CODEC_SET_OF) ret = visitor.visitSetOf(ctx, this);
            else if (codec == CODEC_ANY) ret = visitor.visitAny(ctx, this);
            else if (codec == CODEC_CHOICE) ret = visitor.visitChoice(ctx, this);
            else throw Errors.newASN1Error(ctx.getRuntime(), "Unknown codec " + codec.asJavaString());
            visitor.postCallback(ctx, this);
            return ret;
        }
        
        void parse(ThreadContext ctx, IRubyObject recv) {
            if (!isParsed) {
                /* TODO: handle tagging */
                accept(ctx, new ParseVisitor(recv));
            }
        }
        
        static void decode(ThreadContext ctx, Value v) {
            Asn1Template template = v.getTemplate();
            if (!template.isDecoded()) {
                template.accept(ctx, new DecodeVisitor(v));
            }
        }
    }
    
    private interface CodecVisitor<T> {
        public T visitPrimitive(ThreadContext ctx, Asn1Template t);
        public T visitTemplate(ThreadContext ctx, Asn1Template t);
        public T visitSequence(ThreadContext ctx, Asn1Template t);
        public T visitSet(ThreadContext ctx, Asn1Template t);
        public T visitSequenceOf(ThreadContext ctx, Asn1Template t);
        public T visitSetOf(ThreadContext ctx, Asn1Template t);
        public T visitAny(ThreadContext ctx, Asn1Template t);
        public T visitChoice(ThreadContext ctx, Asn1Template t);
        public void postCallback(ThreadContext ctx, Asn1Template t);
    }
    
    private static class Matcher {
        private Matcher() {}
        
        public static void matchTagAndClass(ThreadContext ctx,
                                                  impl.krypt.asn1.Header header, 
                                                  Integer tag, 
                                                  String tagging, 
                                                  int defaultTag) {
            matchTag(ctx, header, tag, defaultTag);
            matchTagClass(ctx, header, tagging);
        }
        
        private static void matchTag(ThreadContext ctx,
                                    impl.krypt.asn1.Header header,
                                    Integer tag,
                                    int defaultTag) {
            int expected, actual = header.getTag().getTag();
            
            if (tag != null)
                expected = tag;
            else
                expected = defaultTag;
            if (actual != expected)
                throw Errors.newASN1Error(ctx.getRuntime(), "Tag mismatch. Expected: " + expected + " Got: " + actual);
        }
        
        private static void matchTagClass(ThreadContext ctx, impl.krypt.asn1.Header header, String tagging) {
            TagClass expected, actual = header.getTag().getTagClass();
            
            if (tagging == null)
                expected = TagClass.UNIVERSAL;
            else
                expected = TagClass.forName(tagging);
            if (!actual.equals(expected))
                throw Errors.newASN1Error(ctx.getRuntime(), "Tag class mismatch. Expected: " + expected + " Got: " + actual);
        }
    }
    
    private static class ParseVisitor implements CodecVisitor<Void> {
        private final IRubyObject recv;

        public ParseVisitor(IRubyObject recv) {
            this.recv = recv;
        }
        
        @Override
        public Void visitAny(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitChoice(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitPrimitive(ThreadContext ctx, Asn1Template t) {
            Ruby runtime = ctx.getRuntime();
            RubyHash definition = t.getDefinition();
            IRubyObject name = (IRubyObject) definition.get(NAME);
            int defaultTag = long2Int((Long) definition.get(TYPE));
            RubyHash options = (RubyHash) definition.get(OPTIONS);
            Integer tag = options == null ? null : long2Int((Long) options.get(TAG));
            String tagging = options == null ? null : (String) options.get(TAGGING);
            Asn1Object object = t.getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            
            Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag);
            if (h.getTag().isConstructed())
                throw Errors.newASN1Error(ctx.getRuntime(), "Constructive bit set");
            /* name is a symbol with a leading @ */
            recv.getInstanceVariables().setInstanceVariable(name.asJavaString().substring(1), new Value(runtime, t));
            return null;
        }

        @Override
        public Void visitSequence(ThreadContext ctx, Asn1Template t) {
            return visitConstructive(ctx, t, Asn1Tags.SEQUENCE);
        }

        @Override
        public Void visitSequenceOf(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitSet(ThreadContext ctx, Asn1Template t) {
            return visitConstructive(ctx, t, Asn1Tags.SET);
        }

        @Override
        public Void visitSetOf(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitTemplate(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void postCallback(ThreadContext ctx, Asn1Template t) {
            t.setParsed(true);
        }
        
        private Void visitConstructive(ThreadContext ctx, Asn1Template t, int defaultTag) {
            Ruby runtime = ctx.getRuntime();
            RubyHash definition = t.getDefinition();
            RubyArray layout = (RubyArray) definition.get(LAYOUT);
            RubyHash options = (RubyHash) definition.get(OPTIONS);
            Integer tag = options == null ? null : long2Int((Long) options.get(TAG));
            String tagging = options == null ? null : (String) options.get(TAGGING);
            Asn1Object object = t.getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            
            Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag);
            if (!h.getTag().isConstructed())
                throw Errors.newASN1Error(ctx.getRuntime(), "Constructive bit not set");
            
            int numParsed = 0;
            int minSize = long2Int((Long) definition.get(MIN_SIZE));
            int layoutSize = layout.getLength();
            InputStream in = new ByteArrayInputStream(object.getValue());
            Asn1Template current = nextTemplate(runtime, in);
                        
            for (int i=0; i < layoutSize; ++i) {
                RubyHash currentDefinition = (RubyHash) layout.get(i);
                current.setDefinition(currentDefinition);
                try {
                    current.parse(ctx, recv);
                    numParsed++;
                    if (i < layoutSize - 1) {
                        current = nextTemplate(runtime, in);
                    }
                } catch (Exception ex) {
                    /* ignore, no match */
                }
            }
            
            if (numParsed < minSize) {
                throw Errors.newASN1Error(runtime, "Expected "+minSize+".."+layoutSize+" values. Got: "+numParsed);
            }
            if (h.getLength().isInfiniteLength()) {
                parseEoc(runtime, in);
            }
            
            /* invalidate cached encoding */
            object.invalidateValue();
            return null;
        }
        
        private Asn1Template nextTemplate(Ruby runtime, InputStream in) {
            ParsedHeader next = PARSER.next(in);
            if (next == null)
                throw Errors.newASN1Error(runtime, "Premature end of stream detected");
            return new Asn1Template(next.getObject(), null);
        }
        
        private void parseEoc(Ruby runtime, InputStream in) {
            ParsedHeader next = PARSER.next(in);
            if (next == null)
                throw Errors.newASN1Error(runtime, "Premature end of stream detected");
            Tag t = next.getTag();
            if (!(t.getTag() == Asn1Tags.END_OF_CONTENTS && t.getTagClass().equals(TagClass.UNIVERSAL)))
                throw Errors.newASN1Error(runtime, "No closing END OF CONTENTS found for constructive value");
        }
    };
            
    private static class DecodeVisitor implements CodecVisitor<Void> {
        private final IRubyObject recv;

        public DecodeVisitor(IRubyObject recv) {
            this.recv = recv;
        }
        
        @Override
        public Void visitAny(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitChoice(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitPrimitive(ThreadContext ctx, Asn1Template t) {
            Asn1Object object = t.getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            
            if (h.getLength().isInfiniteLength())
                return visitPrimitiveInfiniteLength(ctx, t);
            
            int defaultTag = long2Int((Long) t.getDefinition().get(TYPE));
            Asn1Codec codec = Asn1Codecs.CODECS[defaultTag];
            if (codec == null)
                throw Errors.newASN1Error(ctx.getRuntime(), "No codec available for default tag: " + defaultTag);
            IRubyObject value = codec.decode(new DecodeContext(recv, ctx.getRuntime(), object.getValue()));
            t.setValue(value);
            return null;
        }
        
        private Void visitPrimitiveInfiniteLength(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitSequence(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitSequenceOf(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitSet(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitSetOf(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitTemplate(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void postCallback(ThreadContext ctx, Asn1Template t) {
            t.setDecoded(true);
        }
    };
    
    static int long2Int(Long l) {
        if (l > Integer.MAX_VALUE)
            throw new IllegalArgumentException("Number too large: " + l);
        return l.intValue();
    }
    
    public static class Value extends RubyObject {
        private Asn1Template template;
        
        protected Value(Ruby runtime, Asn1Template template) {
            super(runtime, cValue);
            if (template == null) throw new NullPointerException("template");
            this.template = template;
        }
        
        @JRubyMethod
        public IRubyObject to_s(ThreadContext ctx) {
            return template.getValue().callMethod(ctx, "to_s");
        }
        
        public Asn1Template getTemplate() { return template; }
    }
    
    public static class Parser {
        @JRubyMethod
        public static IRubyObject parse_der(ThreadContext ctx, IRubyObject recv, IRubyObject value) {
            try {
                Ruby rt = ctx.getRuntime();
                InputStream in = Streams.asInputStreamDer(rt, value);
                return generateAsn1Template(ctx, (RubyClass) recv, in);
            } catch(Exception e) {
                throw Errors.newParseError(ctx.getRuntime(), e.getMessage());
            }
        }
        
        private static IRubyObject generateAsn1Template(ThreadContext ctx, RubyClass type, InputStream in) {
            ParsedHeader h = PARSER.next(in);
            Ruby runtime = ctx.getRuntime();
            if (h == null)
                throw Errors.newASN1Error(runtime, "Could not parse template");
            RubyHash definition = (RubyHash) type.instance_variable_get(ctx, runtime.newString("@definition"));
            if (definition == null || definition.isNil()) 
                throw Errors.newASN1Error(runtime, "Type + " + type + " has no ASN.1 definition");
            Asn1Template template = new Asn1Template(h.getObject(), definition);
            return new RubyAsn1Template(runtime, type, template);
        }
    }
    
    private static RubyClass cValue;
    
    private static IRubyObject CODEC;
    private static IRubyObject OPTIONS;
    private static IRubyObject DEFAULT;
    private static IRubyObject NAME;
    private static IRubyObject TYPE;
    private static IRubyObject OPTIONAL;
    private static IRubyObject TAG;
    private static IRubyObject TAGGING;
    private static IRubyObject LAYOUT;
    private static IRubyObject MIN_SIZE;
    
    private static IRubyObject CODEC_PRIMITIVE;
    private static IRubyObject CODEC_SEQUENCE;
    private static IRubyObject CODEC_SET;
    private static IRubyObject CODEC_TEMPLATE;
    private static IRubyObject CODEC_SEQUENCE_OF;
    private static IRubyObject CODEC_SET_OF;
    private static IRubyObject CODEC_CHOICE;
    private static IRubyObject CODEC_ANY;
    
    public static void createTemplate(Ruby runtime, RubyModule mASN1) {
        RubyModule mTemplate = runtime.defineModuleUnder("Template", mASN1);
        RubyModule mParser = runtime.defineModuleUnder("Parser", mTemplate);
        cValue = mTemplate.defineClassUnder("Value", runtime.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);
        
        CODEC = runtime.newSymbol("codec");
        OPTIONS = runtime.newSymbol("options");
        DEFAULT = runtime.newSymbol("default");
        NAME = runtime.newSymbol("name");
        TYPE = runtime.newSymbol("type");
        OPTIONAL = runtime.newSymbol("optional");
        TAG = runtime.newSymbol("tag");
        TAGGING = runtime.newSymbol("tagging");
        LAYOUT = runtime.newSymbol("layout");
        MIN_SIZE = runtime.newSymbol("min_size");
        
        CODEC_PRIMITIVE = runtime.newSymbol("PRIMITIVE");
        CODEC_TEMPLATE = runtime.newSymbol("TEMPLATE");
        CODEC_SEQUENCE = runtime.newSymbol("SEQUENCE");
        CODEC_SET = runtime.newSymbol("SET");
        CODEC_SEQUENCE_OF = runtime.newSymbol("SEQUENCE_OF");
        CODEC_SET_OF = runtime.newSymbol("SET_OF");
        CODEC_ANY = runtime.newSymbol("ANY");
        CODEC_CHOICE = runtime.newSymbol("CHOICE");
        
        mTemplate.defineAnnotatedMethods(RubyAsn1Template.class);
        mParser.defineAnnotatedMethods(Parser.class);
        cValue.defineAnnotatedMethods(Value.class);
    }
}
