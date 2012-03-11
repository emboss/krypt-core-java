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
            ErrorCollector collector = new ErrorCollector();
            try {
                template.parse(ctx, this, collector);
                collector.clear();
                /* ivname has a leading @ */
                Value v = (Value) getInstanceVariable(ivname.substring(1));
                Asn1Template.decode(ctx, v, collector);
                return v.getTemplate().getValue();
            } catch (RuntimeException ex) {
                throw templateError(collector.getErrorMessages(), ctx.getRuntime(), template.getDefinition());
            }
        }
    }
    
    public static class Asn1Template {
        public Asn1Template(Asn1Object object, HashAdapter definition) {
            if (object == null) throw new NullPointerException("object");
            this.object = object;
            this.isParsed = false;
            this.isDecoded = false;
            this.isModified = false;
            this.definition = definition;
        }
        
        private final Asn1Object object;
        private HashAdapter definition;
        private IRubyObject value;
        private boolean isParsed;
        private boolean isDecoded;
        private boolean isModified;

        public Asn1Object getObject() { return this.object; }
        public HashAdapter getDefinition() { return this.definition; }
        public void setDefinition(RubyHash definition) { this.definition = new HashAdapter(definition); }
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
        
        void parse(ThreadContext ctx, IRubyObject recv, ErrorCollector collector) {
            if (!isParsed) {
                /* TODO: handle tagging */
                CodecVisitor<Void> visitor = new ParseVisitor(recv, collector);
                accept(ctx, visitor);
            }
        }
        
        static void decode(ThreadContext ctx, Value v, ErrorCollector collector) {
            Asn1Template template = v.getTemplate();
            if (!template.isDecoded()) {
                template.accept(ctx, new DecodeVisitor(v, collector));
            }
        }
    }
    
    private static RaiseException templateError(String message, Ruby rt, HashAdapter definition) {
        Definition d = new Definition(definition);
        String codec = d.getCodec().asJavaString();
        String name = d.getName().orNull();
        return Errors.newASN1Error(rt, "Error while processing(" + codec + "|" + name +") " + message);
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
    
    private static abstract class ErrorCollectingVisitor implements CodecVisitor<Void> {
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
    
    private static class ParseVisitor extends ErrorCollectingVisitor {
        private final IRubyObject recv;

        public ParseVisitor(IRubyObject recv, ErrorCollector collector) {
            super(collector);
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
            HashAdapter definition = t.getDefinition();
            String name = definition.getSymbol(NAME);
            Integer defaultTag = definition.getIntegerFixnum(TYPE);
            HashAdapter options = definition.getHash(OPTIONS);
            Integer tag = options == null ? null : options.getIntegerFixnum(TAG);
            String tagging = options == null ? null : options.getSymbol(TAGGING);
            Asn1Object object = t.getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            
            if (defaultTag == null) throw Errors.newASN1Error(runtime, "'type' missing in definition");
            Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag);
            if (h.getTag().isConstructed()) throw Errors.newASN1Error(ctx.getRuntime(), "Constructive bit set");
            
            /* name is a symbol with a leading @ */
            recv.getInstanceVariables().setInstanceVariable(name.substring(1), new Value(runtime, t));
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
            Definition d = new Definition(t.getDefinition());
            RubyArray layout = d.getLayout().orThrow(Errors.newASN1Error(runtime, "Constructive type misses 'layout' definition"));
            Integer tag = d.getTag().orNull();
            String tagging = d.getTagging().orNull();
            Asn1Object object = t.getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            
            Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag);
            if (!h.getTag().isConstructed())
                throw Errors.newASN1Error(ctx.getRuntime(), "Constructive bit not set");
            
            int numParsed = 0;
            int minSize = d.getMinSize().orThrow(Errors.newASN1Error(runtime, "Constructive type misses 'min_size' entry"));
            int layoutSize = layout.getLength();
            InputStream in = new ByteArrayInputStream(object.getValue());
            Asn1Template current = nextTemplate(runtime, in);
            ErrorCollector collector = getCollector();
            
            for (int i=0; i < layoutSize; ++i) {
                RubyHash currentDefinition = (RubyHash) layout.get(i);
                current.setDefinition(currentDefinition);
                collector.clear();
                try {
                    current.parse(ctx, recv, collector);
                    numParsed++;
                    if (i < layoutSize - 1) {
                        current = nextTemplate(runtime, in);
                    }
                } catch (Exception ex) {
                    /* ignore, no match */
                }
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
            
    private static class DecodeVisitor extends ErrorCollectingVisitor {
        private final IRubyObject recv;

        public DecodeVisitor(IRubyObject recv, ErrorCollector collector) {
            super(collector);
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
            Definition d = new Definition(t.getDefinition());
            
            if (h.getLength().isInfiniteLength())
                return visitPrimitiveInfiniteLength(ctx, t);
            
            int defaultTag = d.getTypeAsInteger()
                              .orThrow(Errors.newASN1Error(ctx.getRuntime(), "'type' missing in primitive ASN.1 definition"));
            
            Asn1Codec codec = Asn1Codecs.CODECS[defaultTag];
            if (codec == null) throw Errors.newASN1Error(ctx.getRuntime(), "No codec available for default tag: " + defaultTag);
            
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
            Asn1Template template = new Asn1Template(h.getObject(), new HashAdapter(definition));
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
        private final HashAdapter definitionHash;
        private final HashAdapter options;
        
        public Definition(HashAdapter definitionHash) {
            this.definitionHash = definitionHash;
            this.options = this.definitionHash.getHash(OPTIONS);
        }
        
        public IRubyObject getCodec() { return definitionHash.getObject(CODEC); }
        public Optional<String> getName() { return new Optional<String>(definitionHash.getSymbol(NAME)); }
        public Optional<Integer> getTypeAsInteger() { return new Optional<Integer>(definitionHash.getIntegerFixnum(TYPE)); }
        public Optional<RubyArray> getLayout() { return new Optional<RubyArray>(definitionHash.getArray(LAYOUT)); }
        public Optional<Integer> getMinSize() { return new Optional<Integer>(definitionHash.getIntegerFixnum(MIN_SIZE)); }
        
        public boolean getOptional() { 
            if (options == null) return false;
            Boolean b = options.getBoolean(OPTIONAL);
            return b == null ? false : b;
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
