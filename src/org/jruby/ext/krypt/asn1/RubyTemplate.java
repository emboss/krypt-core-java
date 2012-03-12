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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.HashAdapter;
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
        
        protected RubyAsn1Template(Ruby runtime, Asn1Template template) {
            this(runtime, cValue, template);
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
        
        @JRubyMethod
        public IRubyObject to_s(ThreadContext ctx) {
            if (getMetaClass() == cValue) {
                IRubyObject value = template.getValue();
                if (value != null) {
                    return value.callMethod(ctx, "to_s");
                }
            }
            return super.to_s();
        }
        
        private IRubyObject ensureParsedAndDecoded(ThreadContext ctx, String ivname) {
            ErrorCollector collector = new ErrorCollector();
            try {
                if (!template.parse(ctx, this, collector))
                    throw Errors.newASN1Error(ctx.getRuntime(), "Type mismatch");
                collector.clear();
                /* ivname has a leading @ */
                RubyAsn1Template v = (RubyAsn1Template) getInstanceVariable(ivname.substring(1));
                Asn1Template.decode(ctx, v);
                return v.getTemplate().accept(ctx, new ValueVisitor(v));
            } catch (RuntimeException ex) {
                collector.add(ex);
                throw templateError(collector.getErrorMessages(), ctx.getRuntime(), template.getDefinition());
            }
        }
    }
    
    public static class Asn1Template {
        public Asn1Template(Asn1Object object, HashAdapter definition, HashAdapter options) {
            if (object == null) throw new NullPointerException("object");
            this.object = object;
            this.isParsed = false;
            this.isDecoded = false;
            this.isModified = false;
            this.definition = definition;
            this.options = options;
        }
        
        private final Asn1Object object;
        private HashAdapter definition;
        private HashAdapter options;
        private IRubyObject value;
        private boolean isParsed;
        private boolean isDecoded;
        private boolean isModified;

        public Asn1Object getObject() { return this.object; }
        public HashAdapter getDefinition() { return this.definition; }
        public void setDefinition(HashAdapter definition) { this.definition = definition; }
        public HashAdapter getOptions() { return this.options; }
        public void setOptions(HashAdapter options) { this.options = options; }
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
            return ret;
        }
        
        boolean parse(ThreadContext ctx, IRubyObject recv, ErrorCollector collector) {
            if (!isParsed) {
                /* TODO: handle tagging */
                CodecVisitor<Boolean> visitor = new ParseVisitor(recv, collector);
                return accept(ctx, visitor);
            }
            return true;
        }
        
        static void decode(ThreadContext ctx, RubyAsn1Template v) {
            Asn1Template template = v.getTemplate();
            if (!template.isDecoded()) {
                template.accept(ctx, new DecodeVisitor(v));
            }
        }
    }
    
    private static RaiseException templateError(String message, Ruby rt, HashAdapter definition) {
        Definition d = new Definition(definition, null);
        String codec = d.getCodec().asJavaString();
        String name = d.getName().orNull();
        return Errors.newASN1Error(rt, "Error while processing(" + codec + "|" + name +") " + message);
    }
    
    private static byte[] skipExplicitHeader(Asn1Object object) {
        byte[] old = object.getValue();
        impl.krypt.asn1.Header h = PARSER.next(new ByteArrayInputStream(old));
        int headerLen = h.getHeaderLength();
        int newLen = old.length - headerLen;
        byte[] bytes = new byte[newLen];
        System.arraycopy(old, headerLen, bytes, 0, newLen);
        return bytes;
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
    }
    
    private static abstract class ErrorCollectingVisitor<T> implements CodecVisitor<T> {
        private final ErrorCollector collector;
        
        public ErrorCollectingVisitor(ErrorCollector collector) {
            this.collector = collector;
        }
        
        protected ErrorCollector getCollector() {
            return collector;
        }
    }
    
    private static class Matcher {
        private Matcher() {}
        
        public static boolean matchTagAndClass(ThreadContext ctx,
                                                  impl.krypt.asn1.Header header, 
                                                  Integer tag, 
                                                  String tagging, 
                                                  int defaultTag) {
            return matchTag(ctx, header, tag, defaultTag) &&
                   matchTagClass(ctx, header, tagging);
        }
        
        public static boolean matchTag(ThreadContext ctx,
                                    impl.krypt.asn1.Header header,
                                    Integer tag,
                                    int defaultTag) {
            return header.getTag().getTag() == getExpectedTag( tag, defaultTag);
        }
        
        public static boolean matchTagClass(ThreadContext ctx, impl.krypt.asn1.Header header, String tagging) {
            return getExpectedTagClass(tagging) == header.getTag().getTagClass();
        }
        
        public static RaiseException tagMismatch(ThreadContext ctx,
                                                  impl.krypt.asn1.Header header, 
                                                  Integer tag, 
                                                  String tagging, 
                                                  int defaultTag,
                                                  String name) {
            Tag t = header.getTag();
            int actualTag = t.getTag();
            TagClass actualTagClass = t.getTagClass();
            int expectedTag = getExpectedTag(tag, defaultTag);
            TagClass expectedTagClass = getExpectedTagClass(tagging);
            StringBuilder msg = new StringBuilder();
            if (name != null) {
                msg.append("Could not parse ")
                   .append(name)
                   .append(": ");
            }
            if (expectedTag != actualTag) {
                msg.append("Tag mismatch. Expected: ")
                   .append(expectedTag)
                   .append(" Got:")
                   .append(actualTag);
            }
            if (!expectedTagClass.equals(actualTagClass)) {
                msg.append(" Tag class mismatch. Expected:")
                   .append(expectedTagClass)
                   .append(" Got: ")
                   .append(actualTagClass);
            }
            return Errors.newASN1Error(ctx.getRuntime(), msg.toString());
        }
        
        private static int getExpectedTag(Integer tag, int defaultTag) {
            if (tag != null)
                return tag;
            else
                return defaultTag;
        }
        
        private static TagClass getExpectedTagClass(String tagging) {
            if (tagging == null)
                return TagClass.UNIVERSAL;
            else
                return TagClass.forName(tagging);
        }
    }
    
    private static class ParseVisitor extends ErrorCollectingVisitor<Boolean> {
        private final IRubyObject recv;

        public ParseVisitor(IRubyObject recv, ErrorCollector collector) {
            super(collector);
            this.recv = recv;
        }
        
        @Override
        public Boolean visitAny(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Boolean visitChoice(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Boolean visitPrimitive(ThreadContext ctx, Asn1Template t) {
            Ruby runtime = ctx.getRuntime();
            Definition d = new Definition(t.getDefinition(), t.getOptions());
            String name = d.getName().orThrow(Errors.newASN1Error(runtime, "'name' missing in definition"));
            Integer defaultTag = d.getTypeAsInteger().orThrow(Errors.newASN1Error(runtime, "'type' missing in definition"));
            Integer tag = d.getTag().orNull();
            String tagging = d.getTagging().orNull();
            Asn1Object object = t.getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            
            if (!Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag)) {
                if (!d.isOptional())
                    throw Matcher.tagMismatch(ctx, h, tag, tagging, defaultTag, name);
                if (!d.hasDefault()) return false;
            }
            
            /* name is a symbol with a leading @ */
            recv.getInstanceVariables().setInstanceVariable(name.substring(1), new RubyAsn1Template(runtime, t));
            t.setParsed(true);
            return true;
        }

        @Override
        public Boolean visitSequence(ThreadContext ctx, Asn1Template t) {
            return visitConstructive(ctx, t, Asn1Tags.SEQUENCE);
        }

        @Override
        public Boolean visitSequenceOf(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Boolean visitSet(ThreadContext ctx, Asn1Template t) {
            return visitConstructive(ctx, t, Asn1Tags.SET);
        }

        @Override
        public Boolean visitSetOf(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Boolean visitTemplate(ThreadContext ctx, Asn1Template t) {
            Ruby runtime = ctx.getRuntime();
            Definition d = new Definition(t.getDefinition(), t.getOptions());
            RubyClass type = d.getTypeAsClass().orThrow(Errors.newASN1Error(runtime, "'type' missing in ASN.1 definition"));
            String name = d.getName().orThrow(Errors.newASN1Error(runtime, "'name' missing in ASN.1 definition"));
            RubyHash typeDef = (RubyHash) type.instance_variable_get(ctx, runtime.newString("@definition"));
            if (typeDef == null)
                throw Errors.newASN1Error(runtime, type + " has no ASN.1 definition");
            t.setDefinition(new HashAdapter(typeDef));
            RubyAsn1Template instance = new RubyAsn1Template(runtime, type, t);
            recv.getInstanceVariables().setInstanceVariable(name.substring(1), instance);
            /* No further decoding needed */
            /* Do not set parsed flag in order to have constructed value parsed */
            t.setDecoded(true);
            return true;
        }

        private Boolean visitConstructive(ThreadContext ctx, Asn1Template t, int defaultTag) {
            Ruby runtime = ctx.getRuntime();
            Definition d = new Definition(t.getDefinition(), t.getOptions());
            RubyArray layout = d.getLayout().orThrow(Errors.newASN1Error(runtime, "Constructive type misses 'layout' definition"));
            Integer tag = d.getTag().orNull();
            String tagging = d.getTagging().orNull();
            Asn1Object object = t.getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            byte[] bytes;
            
            if (!h.getTag().isConstructed()) {
                if (!d.isOptional())
                    throw Errors.newASN1Error(ctx.getRuntime(), "Mandatory sequence value not found");
                return false;
            }
            if (!Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag)) {
                if (!d.isOptional()) 
                    throw Matcher.tagMismatch(ctx, h, tag, tagging, defaultTag, "Constructive");
                if (d.hasDefault())
                    return true;
                else
                    return false;
            }
            
            if (tagging != null && tagging.equals("EXPLICIT"))
                bytes = skipExplicitHeader(object);
            else
                bytes = object.getValue();
            
            int numParsed = 0;
            int minSize = d.getMinSize().orThrow(Errors.newASN1Error(runtime, "Constructive type misses 'min_size' entry"));
            int layoutSize = layout.getLength();
            InputStream in = new ByteArrayInputStream(bytes);
            Asn1Template current = nextTemplate(runtime, in);
            ErrorCollector collector = getCollector();
            
            for (int i=0; i < layoutSize; ++i) {
                HashAdapter currentDefinition = new HashAdapter((RubyHash) layout.get(i));
                current.setDefinition(currentDefinition);
                current.setOptions(currentDefinition.getHash(OPTIONS));
                collector.clear();
                if (current.parse(ctx, recv, collector)) {
                    numParsed++;
                    if (i < layoutSize - 1) {
                        current = nextTemplate(runtime, in);
                    }
                } /* else didn't match */
            }
            
            if (numParsed < minSize) {
                String rest = collector.getErrorMessages(); 
                throw Errors.newASN1Error(runtime, new StringBuilder()
                        .append("Expected ")
                        .append(minSize)
                        .append("..")
                        .append(layoutSize)
                        .append(" values. Got: ")
                        .append(numParsed)
                        .append(' ')
                        .append(rest).toString());
            }
            if (h.getLength().isInfiniteLength()) {
                parseEoc(runtime, in);
            }
            
            /* invalidate cached encoding */
            object.invalidateValue();
            t.setParsed(true);
            /* No further decoding needed */
            t.setDecoded(true);
            return true;
        }
        
        private Asn1Template nextTemplate(Ruby runtime, InputStream in) {
            ParsedHeader next = PARSER.next(in);
            if (next == null)
                throw Errors.newASN1Error(runtime, "Premature end of stream detected");
            return new Asn1Template(next.getObject(), null, null);
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
            Definition d = new Definition(t.getDefinition(), t.getOptions());
            String tagging = d.getTagging().orNull();
            byte[] bytes;
            
            if (h.getLength().isInfiniteLength())
                return visitPrimitiveInfiniteLength(ctx, t);
            
            if (tagging != null && tagging.equals("EXPLICIT"))
                bytes = skipExplicitHeader(object);
            else
                bytes = object.getValue();
            
            if (h.getTag().isConstructed()) 
                throw Errors.newASN1Error(ctx.getRuntime(), "Constructive bit set");
            
            int defaultTag = d.getTypeAsInteger()
                              .orThrow(Errors.newASN1Error(ctx.getRuntime(), "'type' missing in primitive ASN.1 definition"));
            
            Asn1Codec codec = Asn1Codecs.CODECS[defaultTag];
            if (codec == null) throw Errors.newASN1Error(ctx.getRuntime(), "No codec available for default tag: " + defaultTag);
            
            IRubyObject value = codec.decode(new DecodeContext(recv, ctx.getRuntime(), bytes));
            t.setValue(value);
            t.setDecoded(true);
            return null;
        }
        
        private Void visitPrimitiveInfiniteLength(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitSequence(ThreadContext ctx, Asn1Template t) {
            throw new RuntimeException("Internal error");
        }

        @Override
        public Void visitSequenceOf(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitSet(ThreadContext ctx, Asn1Template t) {
            throw new RuntimeException("Internal error");
        }

        @Override
        public Void visitSetOf(ThreadContext ctx, Asn1Template t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Void visitTemplate(ThreadContext ctx, Asn1Template t) {
            throw new RuntimeException("Internal error");
        }

    };
    
    private static class ValueVisitor implements CodecVisitor<IRubyObject> {
        private final IRubyObject recv;

        public ValueVisitor(IRubyObject recv) {
            this.recv = recv;
        }
        
        @Override
        public IRubyObject visitAny(ThreadContext ctx, Asn1Template t) {
            return t.getValue();
        }

        @Override
        public IRubyObject visitChoice(ThreadContext ctx, Asn1Template t) {
            return t.getValue();
        }

        @Override
        public IRubyObject visitPrimitive(ThreadContext ctx, Asn1Template t) {
            return t.getValue();
        }
        
        @Override
        public IRubyObject visitSequence(ThreadContext ctx, Asn1Template t) {
            return recv;
        }

        @Override
        public IRubyObject visitSequenceOf(ThreadContext ctx, Asn1Template t) {
            return t.getValue();
        }

        @Override
        public IRubyObject visitSet(ThreadContext ctx, Asn1Template t) {
            return recv;
        }

        @Override
        public IRubyObject visitSetOf(ThreadContext ctx, Asn1Template t) {
            return t.getValue();
        }

        @Override
        public IRubyObject visitTemplate(ThreadContext ctx, Asn1Template t) {
            return recv;
        }
    };
    
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
            HashAdapter d = new HashAdapter(definition);
            HashAdapter o = d.getHash(OPTIONS);
            Asn1Template template = new Asn1Template(h.getObject(), d, o);
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
        cValue.defineAnnotatedMethods(RubyAsn1Template.class);
    }
    
    private static class Optional<T> {
        private final T value;

        public Optional(T value) {
            this.value = value;
        }
        
        public T orNull() { return value; }
        
        public T orThrow() {
            if (value == null) throw new RuntimeException("Mandatory argument missing");
            return value;
        }
        
        public T orThrow(RuntimeException t) {
            if (value == null) throw t;
            return value;
        }
    }
    
    private static class Definition {
        private final HashAdapter definition;
        private final HashAdapter options;
        
        public Definition(HashAdapter definition, HashAdapter options) {
            this.definition = definition;
            this.options = options;
        }
        
        public IRubyObject getCodec() { return definition.getObject(CODEC); }
        public Optional<String> getName() { return new Optional<String>(definition.getSymbol(NAME)); }
        public Optional<Integer> getTypeAsInteger() { return new Optional<Integer>(definition.getIntegerFixnum(TYPE)); }
        public Optional<RubyArray> getLayout() { return new Optional<RubyArray>(definition.getArray(LAYOUT)); }
        public Optional<Integer> getMinSize() { return new Optional<Integer>(definition.getIntegerFixnum(MIN_SIZE)); }
        
        public Optional<RubyClass> getTypeAsClass() { 
            IRubyObject type = definition.getObject(TYPE);
            if (type == null) return new Optional<RubyClass>(null);
            return new Optional<RubyClass>((RubyClass) type);
        }
        
        public boolean isOptional() { 
            if (options == null) return false;
            Boolean b = options.getBoolean(OPTIONAL);
            if (b != null && b == true) 
                return true;
            return hasDefault();
        }
        
        public Optional<Integer> getTag() {
            if (options == null) return new Optional<Integer>(null);
            return new Optional<Integer>(options.getIntegerFixnum(TAG));
        }
        
        public Optional<String> getTagging() {
            if (options == null) return new Optional<String>(null);
            return new Optional<String>(options.getSymbol(TAGGING));
        }
        
        public Optional<IRubyObject> getDefault() {
            if (options == null) return new Optional<IRubyObject>(null);
            return new Optional<IRubyObject>(options.getObject(DEFAULT));
        }
        
        public boolean hasDefault() {
            return getDefault().orNull() != null;
        }
    }
    
    /* Don't you just love the verbosity... */
    private static class ErrorCollector implements Collection<Throwable> {
        private final List<Throwable> inner = new ArrayList<Throwable>();

        @Override public boolean add(Throwable e) { return inner.add(e); }
        @Override public boolean addAll(Collection<? extends Throwable> c) { return inner.addAll(c); }
        @Override public void clear() { inner.clear(); }
        @Override public boolean contains(Object o) { return inner.contains(o); }
        @Override public boolean containsAll(Collection<?> c) { return inner.containsAll(c); }
        @Override public boolean isEmpty() { return inner.isEmpty(); }
        @Override public Iterator<Throwable> iterator() { return inner.iterator(); }
        @Override public boolean remove(Object o) { return inner.remove(o); }
        @Override public boolean removeAll(Collection<?> c) { return inner.removeAll(c); }
        @Override public boolean retainAll(Collection<?> c) { return inner.retainAll(c); }
        @Override public int size() { return inner.size(); }
        @Override public Object[] toArray() { return inner.toArray(); }
        @Override public <T> T[] toArray(T[] a) { return inner.toArray(a); }
        
        public String getErrorMessages() {
            StringBuilder b = new StringBuilder();
            for (Throwable t : inner) {
                b.append(": ").append(t.getMessage());
            }
            return b.toString();
        }
    }
}
