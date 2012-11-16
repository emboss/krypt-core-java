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
import impl.krypt.asn1.Header;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.HashAdapter;
import org.jruby.ext.krypt.Streams;
import org.jruby.ext.krypt.asn1.TemplateParser.CodecStrategyVisitor;
import org.jruby.ext.krypt.asn1.TemplateParser.ParseContext;
import org.jruby.ext.krypt.asn1.TemplateParser.ParseStrategy;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class RubyTemplate {
    
    protected interface CodecVisitor<T> {
        public T visitPrimitive();
        public T visitTemplate();
        public T visitSequence();
        public T visitSet();
        public T visitSequenceOf();
        public T visitSetOf();
        public T visitAny();
        public T visitChoice();
    }
    
    public static class RubyAsn1Template extends RubyObject {
        
        public static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby ruby, RubyClass type) {
                return new RubyAsn1Template(ruby, type, null);
            }
        };
        
        private Asn1Template template;
        
        protected RubyAsn1Template(Ruby runtime, RubyClass type, Asn1Template template) {
            super(runtime, type);
            this.template = template;
        }
        
        protected RubyAsn1Template(Ruby runtime, Asn1Template template) {
            this(runtime, cTemplateValue, template);
        }
        
        public Asn1Template getTemplate() { return this.template; }
        protected void setTemplate(Asn1Template template) { this.template = template; }
        
        @JRubyMethod
        public IRubyObject initialize(ThreadContext ctx, final Block block) {
            Ruby runtime = ctx.getRuntime();
            RubyClass type = getMetaClass();
            RubyHash definition = (RubyHash) type.instance_variable_get(ctx, runtime.newString("@definition"));
            if (definition == null || definition.isNil()) 
                throw Errors.newASN1Error(runtime, "Type + " + type + " has no ASN.1 definition");
            HashAdapter d = new HashAdapter(definition);
            HashAdapter o = d.getHash(OPTIONS);
            this.template = new Asn1Template(null, d, o);
            this.template.setParsed(true);
            this.template.setDecoded(true);
            if (block.isGiven()) {
                block.arity().checkArity(runtime, 1);
                block.yield(ctx, this);
            }
            return this;    
        }
        
        @JRubyMethod(name={"_get_callback"})
        public IRubyObject get_callback(ThreadContext ctx, IRubyObject ivname) {
            String name = ivname.asJavaString().substring(1);
            return ensureParsedAndDecoded(ctx, name);
        }
        
        @JRubyMethod(name={"_get_callback_choice"})
        public IRubyObject get_callback_choice(ThreadContext ctx, IRubyObject ivname) {
            String name = ivname.asJavaString().substring(1);
            if (name.equals("tag") || name.equals("type")) {
                ensureParsedAndDecoded(ctx, "value");
                return getInstanceVariable(name);
            }
            return get_callback(ctx, ivname);
        }
        
        @JRubyMethod(name={"_set_callback"})
        public IRubyObject set_callback(ThreadContext ctx, IRubyObject ivname, IRubyObject value) {
            String name = ivname.asJavaString().substring(1);
            RubyAsn1Template container = (RubyAsn1Template) getInstanceVariable(name);
            if (container == null) {
                Asn1Template t = new Asn1Template(null, null, null);
                t.setParsed(true);
                t.setDecoded(true);
                container = new RubyAsn1Template(ctx.getRuntime(), cTemplateValue, t);
                setInstanceVariable(name, container);
            }
            container.getTemplate().setValue(value);
            template.setModified(true);
            return value;
        }
        
        @JRubyMethod(name={"_set_callback_choice"})
        public IRubyObject set_callback_choice(ThreadContext ctx, IRubyObject ivname, IRubyObject value) {
            String name = ivname.asJavaString().substring(1);
            if (name.equals("tag") || name.equals("type")) {
                return setInstanceVariable(name, value);
            }
            return set_callback(ctx, ivname, value);
        }
        
        @JRubyMethod
        public IRubyObject to_der(ThreadContext ctx) {
            try {
                Asn1Object object = template.getObject();
                Header h = object.getHeader();
                if (object != null && (object.getValue() != null || h.getLength().getLength() == 0)) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    object.encodeTo(baos);
                    return ctx.getRuntime().newString(new ByteList(baos.toByteArray(), false));
                }
                throw new UnsupportedOperationException("Not implemented yet.");
            } catch (IOException ex) {
                throw Errors.newASN1Error(ctx.getRuntime(), ex.getMessage());
            }
        }
        
        @JRubyMethod(name={"<=>"})
        public IRubyObject compare(ThreadContext ctx, IRubyObject other) {
            Ruby runtime = ctx.getRuntime();
            if (!other.respondsTo("to_der")) return runtime.getNil();
            return RubyNumeric.int2fix(runtime, 
                                       RubyAsn1.compareSetOfOrder(runtime, 
                                                                  to_der(ctx).asString().getBytes(), 
                                                                  Streams.toDer(other).asString().getBytes()));
        }
        
        @JRubyMethod(meta=true, name={"_mod_included_callback"})
        public static IRubyObject mod_included_callback(ThreadContext ctx, IRubyObject recv, IRubyObject base) {
            RubyClass baseClass = (RubyClass)base;
            baseClass.setAllocator(ALLOCATOR);
            return ctx.getRuntime().getNil();
        }
        
        @JRubyMethod
        public IRubyObject to_s(ThreadContext ctx) {
            if (getMetaClass() == cTemplateValue) {
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
                if (!template.isParsed()) {
                    ParseStrategy s = template.accept(ctx, CodecStrategyVisitor.INSTANCE);
                    parse(ctx, this, template, s, collector);
                    collector.clear();
                }
                RubyAsn1Template v = (RubyAsn1Template) getInstanceVariable(ivname);
                if (v == null)
                    return ctx.getRuntime().getNil();
                Asn1Template valueTemplate = v.getTemplate();
                if (!(valueTemplate.isParsed() && valueTemplate.isDecoded())) {
                    ParseStrategy s = valueTemplate.accept(ctx, CodecStrategyVisitor.INSTANCE);
                    if (!valueTemplate.isParsed()) {
                        parse(ctx, v, valueTemplate, s, collector);
                        collector.clear();
                    }
                    if (!valueTemplate.isDecoded()) {
                        decode(ctx, v, valueTemplate, s, collector);
                    }
                }
                return valueTemplate.getValue();
            } catch (RuntimeException ex) {
                throw templateError(ctx, collector.getErrorMessages(), template.getDefinition());
            }
        }
        
        private static void parse(ThreadContext ctx, IRubyObject recv, Asn1Template template, ParseStrategy s, ErrorCollector collector) {
            Definition d = new Definition(template.getDefinition(), template.getOptions());
            ParseContext parseCtx = new ParseContext(ctx, recv, template, d, collector);
            if (!s.match(parseCtx.asMatchContext()).isSuccess())
                throw collector.addAndReturn(Errors.newASN1Error(ctx.getRuntime(), "Type mismatch"));
            s.parse(parseCtx);
        }
        
        private static void decode(ThreadContext ctx, IRubyObject recv, Asn1Template template, ParseStrategy s, ErrorCollector collector) {
            Definition d = new Definition(template.getDefinition(), template.getOptions());
            s.decode(new ParseContext(ctx, recv, template, d, collector));
        }
    }
    
    public static class Asn1Template {
        public Asn1Template(Asn1Object object, HashAdapter definition, HashAdapter options) {
            this.object = object;
            this.isParsed = false;
            this.isDecoded = false;
            this.isModified = false;
            this.definition = definition;
            this.options = options;
        }
        
        private Asn1Object object;
        private HashAdapter definition;
        private HashAdapter options;
        private IRubyObject value;
        private boolean isParsed;
        private boolean isDecoded;
        private boolean isModified;
        private int matchedLayout;

        public Asn1Object getObject() { return this.object; }
        public void setObject(Asn1Object object) { this.object = object; }
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
        public int getMatchedLayoutIndex() { return this.matchedLayout; }
        public void setMatchedLayoutIndex(int matchedIndex) { this.matchedLayout = matchedIndex; }
        
        protected <T> T accept(ThreadContext ctx, CodecVisitor<T> visitor) {
            IRubyObject codec = ((IRubyObject) definition.get(CODEC));
            
            if (codec == CODEC_PRIMITIVE) return visitor.visitPrimitive();
            else if (codec == CODEC_TEMPLATE) return visitor.visitTemplate();
            else if (codec == CODEC_SEQUENCE) return visitor.visitSequence();
            else if (codec == CODEC_SET) return visitor.visitSet();
            else if (codec == CODEC_SEQUENCE_OF) return visitor.visitSequenceOf();
            else if (codec == CODEC_SET_OF) return visitor.visitSetOf();
            else if (codec == CODEC_ANY) return visitor.visitAny();
            else if (codec == CODEC_CHOICE) return visitor.visitChoice();
            else throw Errors.newASN1Error(ctx.getRuntime(), "Unknown codec " + codec.asJavaString());
        }
    }
    
    private static RaiseException templateError(ThreadContext ctx, String message, HashAdapter definition) {
        Definition d = new Definition(definition, null);
        String codec = d.getCodec(ctx).asJavaString();
        String name = d.getName().orNull();
        return Errors.newASN1Error(ctx.getRuntime(), "Error while processing(" + codec + "|" + name +") " + message);
    }
    
    protected static RubyModule mTemplate;
    protected static RubyClass cTemplateValue;
    
    protected static IRubyObject CODEC;
    protected static IRubyObject OPTIONS;
    protected static IRubyObject DEFAULT;
    protected static IRubyObject NAME;
    protected static IRubyObject TYPE;
    protected static IRubyObject OPTIONAL;
    protected static IRubyObject TAG;
    protected static IRubyObject TAGGING;
    protected static IRubyObject LAYOUT;
    protected static IRubyObject MIN_SIZE;
    
    protected static IRubyObject CODEC_PRIMITIVE;
    protected static IRubyObject CODEC_SEQUENCE;
    protected static IRubyObject CODEC_SET;
    protected static IRubyObject CODEC_TEMPLATE;
    protected static IRubyObject CODEC_SEQUENCE_OF;
    protected static IRubyObject CODEC_SET_OF;
    protected static IRubyObject CODEC_CHOICE;
    protected static IRubyObject CODEC_ANY;
    
    public static void createTemplate(Ruby runtime, RubyModule mASN1) {
        mTemplate = runtime.defineModuleUnder("Template", mASN1);
        RubyModule mParser = runtime.defineModuleUnder("Parser", mTemplate);
        cTemplateValue = mTemplate.defineClassUnder("Value", runtime.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);
        
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
        mParser.defineAnnotatedMethods(TemplateParser.class);
        cTemplateValue.defineAnnotatedMethods(RubyAsn1Template.class);
    }
    
    protected static class Optional<T> {
        private final T value;

        public Optional(T value) {
            this.value = value;
        }
        
        public T orNull() { 
            if (value == null)
                return value;
            if (value instanceof IRubyObject) {
                if (((IRubyObject) value).isNil())
                    return null;
            }
            return value;
        }
        
        public T orThrow() {
            return orThrow(new RuntimeException("Mandatory argument missing"));
        }
        
        public T orThrow(RuntimeException e) {
            T t = orNull();
            if (t == null) throw e;
            return t;
        }
        
        public T orCollectAndThrow(RuntimeException e, ErrorCollector collector) {
            T t = orNull();
            if (t == null) {
                collector.add(e);
                throw e;
            }
            return t;
        }
    }
    
    protected static class Definition {
        private final HashAdapter definition;
        private final HashAdapter options;
        private Integer matchIndex;
        
        public Definition(HashAdapter definition, HashAdapter options) {
            this.definition = definition;
            this.options = options;
        }
        
        public HashAdapter getDefinition() { return definition; }
        public HashAdapter getOptions() { return options; }
        public IRubyObject getCodec(ThreadContext ctx) { return definition.getObject(ctx, CODEC); }
        public Optional<String> getName() { return new Optional<String>(definition.getSymbol(NAME)); }
        public Optional<Integer> getTypeAsInteger() { return new Optional<Integer>(definition.getIntegerFixnum(TYPE)); }
        public Optional<RubyArray> getLayout() { return new Optional<RubyArray>(definition.getArray(LAYOUT)); }
        public Optional<Integer> getMinSize() { return new Optional<Integer>(definition.getIntegerFixnum(MIN_SIZE)); }
        public Integer getMatchedIndex() { return matchIndex; }
        public void setMatchedIndex(Integer idx) { this.matchIndex = idx; }
        
        public Optional<RubyClass> getTypeAsClass(ThreadContext ctx) { 
            IRubyObject type = definition.getObject(ctx, TYPE);
            if (type == null) return new Optional<RubyClass>(null);
            return new Optional<RubyClass>((RubyClass) type);
        }
        
        public Optional<IRubyObject> getTypeAsObject(ThreadContext ctx) {
            IRubyObject type = definition.getObject(ctx, TYPE);
            if (type == null) return new Optional<IRubyObject>(ctx.getRuntime().getNil());
            return new Optional<IRubyObject>(type);
        }
        
        public boolean isOptional(ThreadContext ctx) { 
            if (options == null) return false;
            Boolean b = options.getBoolean(OPTIONAL);
            if (b != null && b == true) 
                return true;
            return hasDefault(ctx);
        }
        
        public Optional<Integer> getTagAsInteger() {
            if (options == null) return new Optional<Integer>(null);
            return new Optional<Integer>(options.getIntegerFixnum(TAG));
        }
        
        public Optional<IRubyObject> getTagAsObject(ThreadContext ctx) {
            if (options == null) return new Optional<IRubyObject>(ctx.getRuntime().getNil());
            IRubyObject tag = options.getObject(ctx, TAG);
            if (tag == null) return new Optional<IRubyObject>(ctx.getRuntime().getNil());
            return new Optional<IRubyObject>(tag);
        }
        
        public Optional<String> getTagging() {
            if (options == null) return new Optional<String>(null);
            return new Optional<String>(options.getSymbol(TAGGING));
        }
        
        public Optional<IRubyObject> getDefault(ThreadContext ctx) {
            if (options == null) return new Optional<IRubyObject>(null);
            return new Optional<IRubyObject>(options.getObject(ctx, DEFAULT));
        }
        
        public boolean hasDefault(ThreadContext ctx) {
            return getDefault(ctx).orNull() != null;
        }
        
        protected <T> T accept(ThreadContext ctx, CodecVisitor<T> visitor) {
            IRubyObject codec = ((IRubyObject) definition.get(CODEC));
            
            if (codec == CODEC_PRIMITIVE) return visitor.visitPrimitive();
            else if (codec == CODEC_TEMPLATE) return visitor.visitTemplate();
            else if (codec == CODEC_SEQUENCE) return visitor.visitSequence();
            else if (codec == CODEC_SET) return visitor.visitSet();
            else if (codec == CODEC_SEQUENCE_OF) return visitor.visitSequenceOf();
            else if (codec == CODEC_SET_OF) return visitor.visitSetOf();
            else if (codec == CODEC_ANY) return visitor.visitAny();
            else if (codec == CODEC_CHOICE) return visitor.visitChoice();
            else throw Errors.newASN1Error(ctx.getRuntime(), "Unknown codec " + codec.asJavaString());
        }
    }
    
    /* Don't you just love the verbosity... */
    protected static class ErrorCollector implements Collection<Throwable> {
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
        
        public RuntimeException addAndReturn(RuntimeException e) {
            add(e);
            return e;
        }
    }
}
