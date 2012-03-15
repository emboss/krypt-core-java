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
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class RubyTemplate {
    
    static final impl.krypt.asn1.Parser PARSER = new ParserFactory().newHeaderParser();
    
    private static class ParseContext {
        private final ThreadContext ctx;
        private final IRubyObject recv;
        private final Asn1Template template;
        private final ErrorCollector collector;
        private Definition definition;
        
        public ParseContext(ThreadContext ctx, IRubyObject recv, Asn1Template template, Definition definition, ErrorCollector collector) {
            this.ctx = ctx;
            this.recv = recv;
            this.template = template;
            this.definition = definition;
            this.collector = collector;
        }

        public ErrorCollector getCollector() { return collector; }
        public ThreadContext getCtx() { return ctx; }
        public IRubyObject getReceiver() { return recv; }
        public Definition getDefinition() { return definition; }
        public void setDefinition(Definition d) { this.definition = d; }
        public Asn1Template getTemplate() { return template; }
    }
    
    private interface ParseStrategy {
        public enum MatchResult {
            MATCHED,
            MATCHED_BY_DEFAULT,
            NO_MATCH;
            
            public boolean isSuccess() {
                return MATCHED.equals(this) || MATCHED_BY_DEFAULT.equals(this);
            }
        }
        public MatchResult match(ParseContext ctx);
        public void parse(ParseContext ctx);
        public void decode(ParseContext ctx);
    }
    
    private interface CodecVisitor<T> {
        public T visitPrimitive();
        public T visitTemplate();
        public T visitSequence();
        public T visitSet();
        public T visitSequenceOf();
        public T visitSetOf();
        public T visitAny();
        public T visitChoice();
    }
    
    private static class CodecStrategyVisitor implements CodecVisitor<ParseStrategy> {
        private CodecStrategyVisitor() {}
        private static final CodecStrategyVisitor INSTANCE = new CodecStrategyVisitor();
        
        public @Override ParseStrategy visitPrimitive() { return PRIMITIVE_PARSER; }
        public @Override ParseStrategy visitTemplate() { return TEMPLATE_PARSER; }
        public @Override ParseStrategy visitSequence() { return SEQUENCE_PARSER; }
        public @Override ParseStrategy visitSet() { return SET_PARSER; }
        public @Override ParseStrategy visitSequenceOf() { return SEQUENCE_OF_PARSER; }
        public @Override ParseStrategy visitSetOf() { return SET_OF_PARSER; }
        public @Override ParseStrategy visitAny() { return ANY_PARSER; }
        public @Override ParseStrategy visitChoice() { return CHOICE_PARSER; }
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
            this(runtime, cValue, template);
        }
        
        public Asn1Template getTemplate() { return this.template; }
        
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
        
        @JRubyMethod
        public IRubyObject get_callback(ThreadContext ctx, IRubyObject ivname) {
            String name = ivname.asJavaString();
            return ensureParsedAndDecoded(ctx, name);
        }
        
        @JRubyMethod
        public IRubyObject set_callback(ThreadContext ctx, IRubyObject ivname, IRubyObject value) {
            String name = ivname.asJavaString().substring(1);
            RubyAsn1Template container = (RubyAsn1Template) getInstanceVariable(name);
            if (container == null) {
                Asn1Template t = new Asn1Template(null, null, null);
                t.setParsed(true);
                t.setDecoded(true);
                container = new RubyAsn1Template(ctx.getRuntime(), cValue, t);
                setInstanceVariable(name, container);
            }
            container.getTemplate().setValue(value);
            template.setModified(true);
            return value;
        }
        
        @JRubyMethod(meta=true)
        public static IRubyObject mod_included_callback(ThreadContext ctx, IRubyObject recv, IRubyObject base) {
            RubyClass baseClass = (RubyClass)base;
            baseClass.setAllocator(ALLOCATOR);
            return ctx.getRuntime().getNil();
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
                if (!template.isParsed()) {
                    ParseStrategy s = template.accept(ctx, CodecStrategyVisitor.INSTANCE);
                    parse(ctx, this, template, s, collector);
                    collector.clear();
                }
                /* ivname has a leading @ */
                RubyAsn1Template v = (RubyAsn1Template) getInstanceVariable(ivname.substring(1));
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
                collector.add(ex);
                throw templateError(ctx, collector.getErrorMessages(), template.getDefinition());
            }
        }
        
        private static void parse(ThreadContext ctx, IRubyObject recv, Asn1Template template, ParseStrategy s, ErrorCollector collector) {
            if (template.isParsed())
                return;
            Definition d = new Definition(template.getDefinition(), template.getOptions());
            ParseContext parseCtx = new ParseContext(ctx, recv, template, d, collector);
            if (!s.match(parseCtx).isSuccess())
                throw collector.addAndReturn(Errors.newASN1Error(ctx.getRuntime(), "Type mismatch"));
            s.parse(parseCtx);
        }
        
        private static void decode(ThreadContext ctx, IRubyObject recv, Asn1Template template, ParseStrategy s, ErrorCollector collector) {
            if (template.isDecoded())
                return;
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
        
        private <T> T accept(ThreadContext ctx, CodecVisitor<T> visitor) {
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
    
    private static byte[] skipExplicitHeader(Asn1Object object) {
        byte[] old = object.getValue();
        impl.krypt.asn1.Header h = PARSER.next(new ByteArrayInputStream(old));
        int headerLen = h.getHeaderLength();
        int newLen = old.length - headerLen;
        byte[] bytes = new byte[newLen];
        System.arraycopy(old, headerLen, bytes, 0, newLen);
        return bytes;
    }
    
    private static void setDefaultValue(ParseContext pctx, Definition definition) {
        ThreadContext ctx = pctx.getCtx();
        Ruby runtime = ctx.getRuntime();
        ErrorCollector collector = pctx.getCollector();
        IRubyObject defaultValue = definition.getDefault(ctx).orThrow();
        String name = definition.getName().orCollectAndThrow(Errors.newASN1Error(runtime, "'name' missing in ASN.1 definition"), collector);
        Asn1Template newTemplate = new Asn1Template(null, definition.getDefinition(), definition.getOptions());
        newTemplate.setValue(defaultValue);
        newTemplate.setParsed(true);
        newTemplate.setDecoded(true);
        pctx.getReceiver()
            .getInstanceVariables()
            .setInstanceVariable(name.substring(1), new RubyAsn1Template(runtime, newTemplate));
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
    
    private static final ParseStrategy PRIMITIVE_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(ParseContext pctx) {
            ThreadContext ctx = pctx.getCtx();
            Definition definition = pctx.getDefinition();
            ErrorCollector collector = pctx.getCollector();
            Ruby runtime = ctx.getRuntime();
            Integer defaultTag = definition.getTypeAsInteger()
                                 .orCollectAndThrow(Errors.newASN1Error(runtime, "'type' missing in definition"), collector);
            Integer tag = definition.getTag().orNull();
            String tagging = definition.getTagging().orNull();
            Asn1Object object = pctx.getTemplate().getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            
            if (Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag))
                return MatchResult.MATCHED;
            
            String name = definition.getName()
                          .orCollectAndThrow(Errors.newASN1Error(runtime, "'name' missing in definition"), collector);
            
            if (!definition.isOptional(ctx))
                throw collector.addAndReturn(Matcher.tagMismatch(ctx, h, tag, tagging, defaultTag, name));
            
            if (definition.hasDefault(ctx)) { 
                setDefaultValue(pctx, definition);
                return MatchResult.MATCHED_BY_DEFAULT;
            }
            
            return MatchResult.NO_MATCH;
        }

        @Override
        public void parse(ParseContext pctx) {
            ThreadContext ctx = pctx.getCtx();
            Definition definition = pctx.getDefinition();
            Ruby runtime = ctx.getRuntime();
            ErrorCollector collector = pctx.getCollector();
            String name = definition.getName()
                          .orCollectAndThrow(Errors.newASN1Error(runtime, "'name' missing in definition"), collector);
            /* name is a symbol with a leading @ */
            Asn1Template template = pctx.getTemplate();
            pctx.getReceiver()
                .getInstanceVariables()
                .setInstanceVariable(name.substring(1), new RubyAsn1Template(runtime, template));
            template.setParsed(true);
        }

        @Override
        public void decode(ParseContext pctx) {
            ThreadContext ctx = pctx.getCtx();
            ErrorCollector collector = pctx.getCollector();
            Asn1Template template = pctx.getTemplate();
            Asn1Object object = template.getObject();
            impl.krypt.asn1.Header h = object.getHeader();
            Definition definition = pctx.getDefinition();
            String tagging = definition.getTagging().orNull();
            byte[] bytes;
            
            if (h.getLength().isInfiniteLength()) {
                decodeInfiniteLength(pctx);
                return;
            }
            
            if (tagging != null && tagging.equals("EXPLICIT")) {
                if (!h.getTag().isConstructed()) 
                    throw collector.addAndReturn(Errors.newASN1Error(ctx.getRuntime(), "Constructive bit not set for explicitly tagged value"));
                bytes = skipExplicitHeader(object);
            } else {
                if (h.getTag().isConstructed()) 
                    throw collector.addAndReturn(Errors.newASN1Error(ctx.getRuntime(), "Constructive bit set"));
                bytes = object.getValue();
            }
            
            int defaultTag = definition.getTypeAsInteger()
                             .orCollectAndThrow(Errors.newASN1Error(ctx.getRuntime(), "'type' missing in primitive ASN.1 definition"), collector);
            
            Asn1Codec codec = Asn1Codecs.CODECS[defaultTag];
            if (codec == null) 
                throw collector.addAndReturn(Errors.newASN1Error(ctx.getRuntime(), "No codec available for default tag: " + defaultTag));
            
            IRubyObject value = codec.decode(new DecodeContext(pctx.getReceiver(), ctx.getRuntime(), bytes));
            template.setValue(value);
            template.setDecoded(true);
        }
        
        private void decodeInfiniteLength(ParseContext pctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    };
    
    private static final ParseStrategy TEMPLATE_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(ParseContext pctx) {
            ThreadContext ctx = pctx.getCtx();
            ErrorCollector collector = pctx.getCollector();
            Asn1Template template = pctx.getTemplate();
            HashAdapter newDefinition = getInnerDefinition(pctx);
            Definition d = new Definition(newDefinition, template.getOptions());
            ParseStrategy s = d.accept(ctx, CodecStrategyVisitor.INSTANCE);
            ParseContext tmp  = new ParseContext(ctx, pctx.getReceiver(), template, d, collector);
            ParseStrategy.MatchResult mr = s.match(tmp);
            if (mr.equals(ParseStrategy.MatchResult.NO_MATCH)) {
                Definition outer = pctx.getDefinition();
                if (outer.hasDefault(ctx)) {
                    setDefaultValue(pctx, outer);
                    return MatchResult.MATCHED_BY_DEFAULT;
                }
            }
            return mr;
        }

        @Override
        public void parse(ParseContext pctx) {
            ThreadContext ctx = pctx.getCtx();
            Ruby runtime = ctx.getRuntime();
            ErrorCollector collector = pctx.getCollector();
            Definition definition = pctx.getDefinition();
            IRubyObject recv = pctx.getReceiver();
            Asn1Template template = pctx.getTemplate();
            String name = definition.getName()
                          .orCollectAndThrow(Errors.newASN1Error(runtime, "'name' missing in ASN.1 definition"), collector);
            RubyClass type = definition.getTypeAsClass(ctx)
                             .orCollectAndThrow(Errors.newASN1Error(runtime, "'type' missing in ASN.1 definition"), collector);
            HashAdapter newDefinition = getInnerDefinition(pctx);
            HashAdapter oldDefinition = template.getDefinition();
            
            template.setDefinition(newDefinition);
            RubyAsn1Template instance = new RubyAsn1Template(runtime, type, template);
            Asn1Template newTemplate = new Asn1Template(null, oldDefinition, definition.getOptions());
            newTemplate.setValue(instance);
            newTemplate.setParsed(true);
            newTemplate.setDecoded(true);
            recv.getInstanceVariables().setInstanceVariable(name.substring(1), new RubyAsn1Template(runtime, cValue, newTemplate));
            /* No further decoding needed */
            /* Do not set parsed flag in order to have constructed value parsed */
            template.setDecoded(true);
            template.setParsed(false);
        }
        
        private HashAdapter getInnerDefinition(ParseContext pctx) {
            Definition definition = pctx.getDefinition();
            ThreadContext ctx = pctx.getCtx();
            Ruby runtime = ctx.getRuntime();
            RubyClass type = definition.getTypeAsClass(ctx)
                             .orCollectAndThrow(Errors.newASN1Error(runtime, "'type' missing in ASN.1 definition"), pctx.getCollector());
            RubyHash typeDef = (RubyHash) type.instance_variable_get(ctx, runtime.newString("@definition"));
            if (typeDef == null)
                throw Errors.newASN1Error(runtime, type + " has no ASN.1 definition");
            return new HashAdapter(typeDef);
        }

        @Override
        public void decode(ParseContext ctx) { /* NO OP */ }
    };
    
    private static final ParseStrategy SEQUENCE_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(ParseContext ctx) {
            return matchCons(ctx, Asn1Tags.SEQUENCE);
        }

        @Override
        public void parse(ParseContext ctx) {
            parseCons(ctx);
        }

        @Override
        public void decode(ParseContext ctx) { /* NO_OP */ }
    };
    
    private static final ParseStrategy SET_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(ParseContext ctx) {
            return matchCons(ctx, Asn1Tags.SET);
        }

        @Override
        public void parse(ParseContext ctx) {
            parseCons(ctx);
        }

        @Override
        public void decode(ParseContext ctx) { /* NO_OP */ }
    };
    
    private static ParseStrategy.MatchResult matchCons(ParseContext pctx, int defaultTag) {
        ThreadContext ctx = pctx.getCtx();
        ErrorCollector collector = pctx.getCollector();
        Definition definition = pctx.getDefinition();
        Integer tag = definition.getTag().orNull();
        String tagging = definition.getTagging().orNull();
        impl.krypt.asn1.Header h = pctx.getTemplate().getObject().getHeader();
        
        if (!h.getTag().isConstructed()) {
            if (!definition.isOptional(ctx))
                throw collector.addAndReturn(Errors.newASN1Error(ctx.getRuntime(), "Mandatory sequence value not found"));
            return ParseStrategy.MatchResult.NO_MATCH;
        }
        if (Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag))
            return ParseStrategy.MatchResult.MATCHED;
        
        if (!definition.isOptional(ctx)) 
                throw collector.addAndReturn(Matcher.tagMismatch(ctx, h, tag, tagging, defaultTag, "Constructive"));
        
        return ParseStrategy.MatchResult.NO_MATCH;
    }
    
    private static void parseCons(ParseContext pctx) {
        ThreadContext ctx = pctx.getCtx();
        Ruby runtime = ctx.getRuntime();
        ErrorCollector collector = pctx.getCollector();
        Definition definition = pctx.getDefinition();
        IRubyObject recv = pctx.getReceiver();
        Asn1Template template = pctx.getTemplate();
        RubyArray layout = definition.getLayout()
                           .orCollectAndThrow(Errors.newASN1Error(runtime, "Constructive type misses 'layout' definition"), collector);
        String tagging = definition.getTagging().orNull();
        Asn1Object object = template.getObject();
        impl.krypt.asn1.Header h = object.getHeader();
        byte[] bytes;

        if (tagging != null && tagging.equals("EXPLICIT"))
            bytes = skipExplicitHeader(object);
        else
            bytes = object.getValue();

        int numParsed = 0;
        int minSize = definition.getMinSize()
                      .orCollectAndThrow(Errors.newASN1Error(runtime, "Constructive type misses 'min_size' entry"), collector);
        int layoutSize = layout.getLength();
        InputStream in = new ByteArrayInputStream(bytes);
        Asn1Template current = nextTemplate(in);
        if (current == null)
            throw collector.addAndReturn(Errors.newASN1Error(runtime, "Reached end of data"));
        
        boolean goOn = true;
        for (int i=0; i < layoutSize && goOn; ++i) {
            HashAdapter currentDefinition = new HashAdapter((RubyHash) layout.get(i));
            collector.clear();
            current.setDefinition(currentDefinition);
            current.setOptions(currentDefinition.getHash(OPTIONS));
            ParseStrategy s = current.accept(ctx, CodecStrategyVisitor.INSTANCE);
            Definition d = new Definition(current.getDefinition(), current.getOptions());
            ParseContext parseCtx = new ParseContext(ctx, recv, current, d, collector);
            ParseStrategy.MatchResult mr = s.match(parseCtx);
            switch (mr) {
                case MATCHED:
                    s.parse(parseCtx);
                    numParsed++;
                    if (i < layoutSize - 1) {
                        current = nextTemplate(in);
                        if (current == null) {
                            checkRestIsOptional(pctx, layout, i+1);
                            goOn = false;
                        }
                    }
                    break;
                default:
                    break;
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
        if (!Streams.isConsumed(in)) {
            throw collector.addAndReturn(Errors.newASN1Error(runtime, "Data left that could not be parsed"));
        }

        /* invalidate cached encoding */
        object.invalidateValue();
        template.setParsed(true);
        /* No further decoding needed */
        template.setDecoded(true);
    }
    
    private static void checkRestIsOptional(ParseContext pctx, RubyArray layout, int index) {
        ThreadContext ctx = pctx.getCtx();
        for (int i=index; i < layout.size(); i++) {
            HashAdapter currentDefinition = new HashAdapter((RubyHash) layout.get(i));
            Definition definition = new Definition(currentDefinition, currentDefinition.getHash(OPTIONS));
            if (!definition.isOptional(ctx)) {
                String name = definition.getName().orNull();
                String msg;
                if (name != null)
                    msg = "Mandatory value " + name + " not found";
                else
                    msg = "Mandatory value not found";
                throw pctx.getCollector().addAndReturn(Errors.newASN1Error(ctx.getRuntime(), msg));
            }
            if (definition.hasDefault(ctx)) {
                setDefaultValue(pctx, definition);
            }
        }
    }
    
    private static Asn1Template nextTemplate(InputStream in) {
        ParsedHeader next = PARSER.next(in);
        if (next == null) return null;
        return new Asn1Template(next.getObject(), null, null);
    }

    private static void parseEoc(Ruby runtime, InputStream in) {
        ParsedHeader next = PARSER.next(in);
        if (next == null)
            throw Errors.newASN1Error(runtime, "Premature end of stream detected");
        Tag t = next.getTag();
        if (!(t.getTag() == Asn1Tags.END_OF_CONTENTS && t.getTagClass().equals(TagClass.UNIVERSAL)))
            throw Errors.newASN1Error(runtime, "No closing END OF CONTENTS found for constructive value");
    }
    
    private static final ParseStrategy SEQUENCE_OF_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void parse(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void decode(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    };
    
    private static final ParseStrategy SET_OF_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void parse(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void decode(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    };
    
    private static final ParseStrategy ANY_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void parse(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void decode(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    };
    
    private static final ParseStrategy CHOICE_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void parse(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void decode(ParseContext ctx) {
            throw new UnsupportedOperationException("Not supported yet.");
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
    
    private static class Definition {
        private final HashAdapter definition;
        private final HashAdapter options;
        
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
        
        public Optional<RubyClass> getTypeAsClass(ThreadContext ctx) { 
            IRubyObject type = definition.getObject(ctx, TYPE);
            if (type == null) return new Optional<RubyClass>(null);
            return new Optional<RubyClass>((RubyClass) type);
        }
        
        public boolean isOptional(ThreadContext ctx) { 
            if (options == null) return false;
            Boolean b = options.getBoolean(OPTIONAL);
            if (b != null && b == true) 
                return true;
            return hasDefault(ctx);
        }
        
        public Optional<Integer> getTag() {
            if (options == null) return new Optional<Integer>(null);
            return new Optional<Integer>(options.getIntegerFixnum(TAG));
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
        
        private <T> T accept(ThreadContext ctx, CodecVisitor<T> visitor) {
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
        
        public RuntimeException addAndReturn(RuntimeException e) {
            add(e);
            return e;
        }
    }
}
