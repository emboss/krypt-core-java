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

import impl.krypt.asn1.Asn1Object;
import impl.krypt.asn1.Header;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.ParserFactory;
import impl.krypt.asn1.Tag;
import impl.krypt.asn1.TagClass;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.RaiseException;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.HashAdapter;
import org.jruby.ext.krypt.Streams;
import org.jruby.ext.krypt.asn1.RubyAsn1.Asn1Codec;
import org.jruby.ext.krypt.asn1.RubyAsn1.DecodeContext;
import org.jruby.ext.krypt.asn1.RubyTemplate.Asn1Template;
import org.jruby.ext.krypt.asn1.RubyTemplate.CodecVisitor;
import org.jruby.ext.krypt.asn1.RubyTemplate.Definition;
import org.jruby.ext.krypt.asn1.RubyTemplate.ErrorCollector;
import org.jruby.ext.krypt.asn1.RubyTemplate.RubyAsn1Template;
import org.jruby.ext.krypt.asn1.TemplateParser.ParseStrategy.MatchResult;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.builtin.InstanceVariables;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class TemplateParser {
    
    private TemplateParser() {}
    
    static final impl.krypt.asn1.Parser PARSER = new ParserFactory().newHeaderParser();
    
    @JRubyMethod
    public static IRubyObject parse_der(ThreadContext ctx, IRubyObject recv, IRubyObject value) {
        try {
            Ruby rt = ctx.getRuntime();
            InputStream in = Streams.asInputStreamDer(rt, value);
            IRubyObject ret = generateAsn1Template(ctx, (RubyClass) recv, in);
            if (ret == null)
                throw Errors.newASN1Error(rt, "Premature end of data");
            return ret;
        } catch(Exception e) {
            throw Errors.newParseError(ctx.getRuntime(), e.getMessage());
        }
    }

    protected static IRubyObject generateAsn1Template(ThreadContext ctx, RubyClass type, InputStream in) {
        ParsedHeader h = PARSER.next(in);
        Ruby runtime = ctx.getRuntime();
        if (h == null)
            return null;
        RubyHash definition = (RubyHash) type.instance_variable_get(ctx, runtime.newString("@definition"));
        if (definition == null || definition.isNil()) 
            throw Errors.newASN1Error(runtime, "Type + " + type + " has no ASN.1 definition");
        HashAdapter d = new HashAdapter(definition);
        HashAdapter o = d.getHash(RubyTemplate.OPTIONS);
        Asn1Template template = new Asn1Template(h.getObject(), d, o);
        return new RubyAsn1Template(runtime, type, template);
    }
    
    protected static interface AbstractParseContext {
        public ErrorCollector getCollector();
        public ThreadContext getCtx();
        public IRubyObject getReceiver();
        public Definition getDefinition();
    }
    
    protected static class ParseContext implements AbstractParseContext {
        private final ThreadContext ctx;
        private final IRubyObject recv;
        private final Asn1Template template;
        private final ErrorCollector collector;
        private final Definition definition;
        
        public ParseContext(ThreadContext ctx, IRubyObject recv, Asn1Template template, Definition definition, ErrorCollector collector) {
            this.ctx = ctx;
            this.recv = recv;
            this.template = template;
            this.definition = definition;
            this.collector = collector;
        }

        @Override public ErrorCollector getCollector() { return collector; }
        @Override public ThreadContext getCtx() { return ctx; }
        @Override public IRubyObject getReceiver() { return recv; }
        @Override public Definition getDefinition() { return definition; }
        public Asn1Template getTemplate() { return template; }
        public MatchContext asMatchContext() {
            return new MatchContext(this);
        }
    }
    
    protected static class MatchContext implements AbstractParseContext {
        private final ParseContext inner;
        private Header header;
        private Definition definition;
        
        public MatchContext(ParseContext pctx) {
            this.inner = pctx;
            this.header = pctx.getTemplate().getObject().getHeader();
            this.definition = pctx.getDefinition();
        }

        @Override public ErrorCollector getCollector() { return inner.getCollector(); }
        @Override public ThreadContext getCtx() { return inner.getCtx(); }
        @Override public IRubyObject getReceiver() { return inner.getReceiver(); }
        @Override public Definition getDefinition() { return definition; }
        public void setDefinition(Definition d) { this.definition = d; }
        public Header getHeader() { return header; }
        public void nextHeader() { 
            Asn1Object object = inner.getTemplate().getObject();
            InputStream in = new ByteArrayInputStream(object.getValue());
            this.header = PARSER.next(in);
        }
        public MatchContext createTemporary(Definition d) {
            MatchContext tmp = new MatchContext(inner);
            tmp.definition = d;
            tmp.header = header;
            return tmp;
        }
    }
    
    protected interface ParseStrategy {
        public enum MatchResult {
            MATCHED,
            MATCHED_BY_DEFAULT,
            NO_MATCH;
            
            public boolean isSuccess() {
                return MATCHED.equals(this) || MATCHED_BY_DEFAULT.equals(this);
            }
        }
        public MatchResult match(MatchContext ctx);
        public void parse(ParseContext ctx);
        public void decode(ParseContext ctx);
    }
    
    protected static class CodecStrategyVisitor implements CodecVisitor<ParseStrategy> {
        private CodecStrategyVisitor() {}
        protected static final CodecStrategyVisitor INSTANCE = new CodecStrategyVisitor();
        
        public @Override ParseStrategy visitPrimitive() { return PRIMITIVE_PARSER; }
        public @Override ParseStrategy visitTemplate() { return TEMPLATE_PARSER; }
        public @Override ParseStrategy visitSequence() { return SEQUENCE_PARSER; }
        public @Override ParseStrategy visitSet() { return SET_PARSER; }
        public @Override ParseStrategy visitSequenceOf() { return SEQUENCE_OF_PARSER; }
        public @Override ParseStrategy visitSetOf() { return SET_OF_PARSER; }
        public @Override ParseStrategy visitAny() { return ANY_PARSER; }
        public @Override ParseStrategy visitChoice() { return CHOICE_PARSER; }
    }
    
    private static class Matcher {
        private Matcher() {}
        
        public static boolean matchTagAndClass(ThreadContext ctx,
                                                  Header header, 
                                                  Integer tag, 
                                                  String tagging, 
                                                  int defaultTag) {
            return matchTag(ctx, header, tag, defaultTag) &&
                   matchTagClass(ctx, header, tagging);
        }
        
        public static boolean matchTag(ThreadContext ctx,
                                    Header header,
                                    Integer tag,
                                    int defaultTag) {
            return header.getTag().getTag() == getExpectedTag( tag, defaultTag);
        }
        
        public static boolean matchTagClass(ThreadContext ctx, Header header, String tagging) {
            return getExpectedTagClass(tagging) == header.getTag().getTagClass();
        }
        
        public static RaiseException tagMismatch(ThreadContext ctx,
                                                  Header header, 
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
        public MatchResult match(MatchContext mctx) {
            ThreadContext ctx = mctx.getCtx();
            Definition definition = mctx.getDefinition();
            ErrorCollector collector = mctx.getCollector();
            Ruby runtime = ctx.getRuntime();
            Integer defaultTag = definition.getTypeAsInteger()
                                 .orCollectAndThrow(Errors.newASN1Error(runtime, "'type' missing in definition"), collector);
            Integer tag = definition.getTagAsInteger().orNull();
            String tagging = definition.getTagging().orNull();
                        
            if (Matcher.matchTagAndClass(ctx, mctx.getHeader(), tag, tagging, defaultTag))
                return MatchResult.MATCHED;
            
            return checkOptionalOrDefault(mctx, defaultTag);
        }

        @Override
        public void parse(ParseContext pctx) {
            parseAndAssign(pctx);
        }

        @Override
        public void decode(ParseContext pctx) {
            ThreadContext ctx = pctx.getCtx();
            ErrorCollector collector = pctx.getCollector();
            Asn1Template template = pctx.getTemplate();
            Asn1Object object = template.getObject();
            Header h = object.getHeader();
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
        public MatchResult match(MatchContext mctx) {
            ThreadContext ctx = mctx.getCtx();
            Definition templateDefinition = mctx.getDefinition();
            HashAdapter templateOptions = templateDefinition.getOptions();
            
            HashAdapter newDefinition = getInnerDefinition(mctx);
            Definition d = new Definition(newDefinition, templateOptions);
            ParseStrategy s = d.accept(ctx, CodecStrategyVisitor.INSTANCE);
            MatchContext tmp  = mctx.createTemporary(d);
            ParseStrategy.MatchResult mr = s.match(tmp);
            if (mr.equals(ParseStrategy.MatchResult.NO_MATCH)) {
                if (templateDefinition.hasDefault(ctx)) {
                    setDefaultValue(mctx);
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
            String name = determineName(definition.getName().orNull());
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
            recv.getInstanceVariables().setInstanceVariable(name, new RubyAsn1Template(runtime, RubyTemplate.cTemplateValue, newTemplate));
            /* No further decoding needed */
            /* Do not set parsed flag in order to have constructed value parsed */
            template.setDecoded(true);
            template.setParsed(false);
        }
        
        private HashAdapter getInnerDefinition(AbstractParseContext pctx) {
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
        public MatchResult match(MatchContext ctx) {
            return matchConstructed(ctx, Asn1Tags.SEQUENCE);
        }

        @Override
        public void parse(ParseContext ctx) {
            parseConstructed(ctx);
        }

        @Override
        public void decode(ParseContext ctx) { /* NO_OP */ }
    };
    
    private static final ParseStrategy SET_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(MatchContext ctx) {
            return matchConstructed(ctx, Asn1Tags.SET);
        }

        @Override
        public void parse(ParseContext ctx) {
            parseConstructed(ctx);
        }

        @Override
        public void decode(ParseContext ctx) { /* NO_OP */ }
    };
    
    private static ParseStrategy.MatchResult matchConstructed(MatchContext mctx, int defaultTag) {
        if (tryMatchConstructed(mctx, defaultTag))
            return ParseStrategy.MatchResult.MATCHED;
        return ParseStrategy.MatchResult.NO_MATCH;
    }
    
    private static void parseConstructed(ParseContext pctx) {
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
        Header h = object.getHeader();
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
            current.setOptions(currentDefinition.getHash(RubyTemplate.OPTIONS));
            ParseStrategy s = current.accept(ctx, CodecStrategyVisitor.INSTANCE);
            Definition d = new Definition(current.getDefinition(), current.getOptions());
            ParseContext innerCtx = new ParseContext(ctx, recv, current, d, collector);
            ParseStrategy.MatchResult mr = s.match(innerCtx.asMatchContext());
            switch (mr) {
                case MATCHED:
                    s.parse(innerCtx);
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
            Definition definition = new Definition(currentDefinition, currentDefinition.getHash(RubyTemplate.OPTIONS));
            if (!definition.isOptional(ctx)) {
                String name = determineName(definition.getName().orNull());
                String msg = "Mandatory value " + name + " not found";
                throw pctx.getCollector().addAndReturn(Errors.newASN1Error(ctx.getRuntime(), msg));
            }
            if (definition.hasDefault(ctx)) {
                MatchContext mctx = pctx.asMatchContext();
                mctx.setDefinition(definition);
                setDefaultValue(mctx);
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
        public MatchResult match(MatchContext ctx) {
            return matchConstructedOf(ctx, Asn1Tags.SEQUENCE);
        }

        @Override
        public void parse(ParseContext ctx) {
            parseAndAssign(ctx);
        }

        @Override
        public void decode(ParseContext ctx) {
            decodeConstructedOf(ctx);
        }
    };
    
    private static final ParseStrategy SET_OF_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(MatchContext ctx) {
            return matchConstructedOf(ctx, Asn1Tags.SET);
        }

        @Override
        public void parse(ParseContext ctx) {
            parseAndAssign(ctx);
        }

        @Override
        public void decode(ParseContext ctx) {
            decodeConstructedOf(ctx);
        }
    };
    
    private static MatchResult matchConstructedOf(MatchContext pctx, int defaultTag) {
        if (tryMatchConstructed(pctx, defaultTag))
            return ParseStrategy.MatchResult.MATCHED;
        return checkOptionalOrDefault(pctx, defaultTag);
    }
    
    private static void decodeConstructedOf(ParseContext pctx) {
        ThreadContext ctx = pctx.getCtx();
        Definition definition = pctx.getDefinition();
        ErrorCollector collector = pctx.getCollector();
        Ruby runtime = ctx.getRuntime();
        String name = determineName(definition.getName().orNull());
        RubyClass type = definition.getTypeAsClass(ctx)
                         .orCollectAndThrow(Errors.newASN1Error(runtime, "'type missing in ASN.1 definition"), collector);
        String tagging = definition.getTagging().orNull();
        Asn1Template template = pctx.getTemplate();
        Asn1Object object = template.getObject();
        Header h = object.getHeader();
        byte[] bytes;

        if (tagging != null && tagging.equals("EXPLICIT"))
            bytes = skipExplicitHeader(object);
        else
            bytes = object.getValue();
        
        InputStream in = new ByteArrayInputStream(bytes);
        RubyArray values;
        
        try {
            if (type.hasModuleInHierarchy(RubyTemplate.mTemplate))
                values = decodeConstructedOfTemplates(ctx, type, in);
            else
                values = decodeConstructedOfPrimitives(ctx, type, in);
        } catch (RuntimeException e) {
            throw collector.addAndReturn(Errors.newASN1Error(runtime, e.getMessage()));
        }
        
        if (values.isEmpty() && !definition.isOptional(ctx)) {
                throw collector.addAndReturn(Errors.newASN1Error(runtime, "Mandatory value " + name + "could not be parsed. Sequence is empty"));
        }
        
        if (h.getLength().isInfiniteLength()) {
            parseEoc(runtime, in);
        }
        if (!Streams.isConsumed(in)) {
            throw collector.addAndReturn(Errors.newASN1Error(runtime, "Data left that could not be parsed"));
        }

        template.setValue(values);
        /* invalidate cached encoding */
        object.invalidateValue();
        template.setDecoded(true);
    }
    
    private static RubyArray decodeConstructedOfTemplates(ThreadContext ctx, RubyClass type, InputStream in) {
        RubyArray ret = ctx.getRuntime().newArray();
        IRubyObject current;
        
        while((current = generateAsn1Template(ctx, type, in)) != null) {
            ret.add(current);
        }
        return ret;
    }
    
    private static RubyArray decodeConstructedOfPrimitives(ThreadContext ctx, RubyClass type, InputStream in) {
        RubyArray ret = ctx.getRuntime().newArray();
        IRubyObject current;
        
        while((current = RubyAsn1.generateAsn1Data(ctx.getRuntime(), in)) != null) {
            if (!current.callMethod(ctx, "kind_of?", type).isTrue())
                throw Errors.newASN1Error(ctx.getRuntime(), "Expected " + type + " but got " + current.getMetaClass());
            ret.add(current);
        }
        return ret;
    }
    
    private static final ParseStrategy ANY_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(MatchContext mctx) {
            ThreadContext ctx = mctx.getCtx();
            Definition definition = mctx.getDefinition();
            if (definition.isOptional(ctx)) {
                Ruby runtime = ctx.getRuntime();
                ErrorCollector collector = mctx.getCollector();
                String name = determineName(definition.getName().orNull());
                String tagging = definition.getTagging().orNull();
                Integer tag = definition.getTagAsInteger().orNull();
                int pseudoDefaultTag = tag;
                
                if (tag == null)
                    throw collector.addAndReturn(Errors.newASN1Error(runtime, "Cannot unambiguously assign ANY value " + name));
                
                if (!Matcher.matchTagAndClass(ctx, mctx.getHeader(), tag, tagging, pseudoDefaultTag)) {
                    if (definition.hasDefault(ctx)) {
                        setDefaultValue(mctx);
                        return MatchResult.MATCHED_BY_DEFAULT;
                    }
                    return MatchResult.NO_MATCH;
                }
            }
            return MatchResult.MATCHED;
        }

        @Override
        public void parse(ParseContext ctx) {
            parseAndAssign(ctx);
        }

        @Override
        public void decode(ParseContext pctx) {
            ThreadContext ctx = pctx.getCtx();
            Definition definition = pctx.getDefinition();
            ErrorCollector collector = pctx.getCollector();
            Ruby runtime = ctx.getRuntime();
            String tagging = definition.getTagging().orNull();
            Asn1Template template = pctx.getTemplate();
            Asn1Object object = template.getObject();
            final Header h = object.getHeader();
            final byte[] bytes;

            if (tagging != null && tagging.equals("EXPLICIT"))
                bytes = skipExplicitHeader(object);
            else
                bytes = object.getValue();

            final Iterator<InputStream> iter = new ArrayList<InputStream>() {{
                add(new ByteArrayInputStream(h.getTag().getEncoding()));
                add(new ByteArrayInputStream(h.getLength().getEncoding()));
                add(new ByteArrayInputStream(bytes));
            }}.iterator();
            
            InputStream in = new SequenceInputStream(new Enumeration<InputStream>() {
                @Override public boolean hasMoreElements() { return iter.hasNext(); }
                @Override public InputStream nextElement() { return iter.next();    }
            });
            
            IRubyObject asn1 = RubyAsn1.generateAsn1Data(runtime, in);
            if (asn1 == null) throw collector.addAndReturn(Errors.newASN1Error(runtime, "Could not parse ANY value"));
            template.setValue(asn1);
            template.setDecoded(true);
        }
    };
    
    private static final ParseStrategy CHOICE_PARSER = new ParseStrategy() {
        @Override
        public MatchResult match(MatchContext mctx) {
            ThreadContext ctx = mctx.getCtx();
            Ruby runtime = ctx.getRuntime();
            ErrorCollector collector = mctx.getCollector();
            Definition definition = mctx.getDefinition();
            RubyArray layout = definition.getLayout()
                               .orCollectAndThrow(Errors.newASN1Error(runtime, "Constructive type misses 'layout' definition"), collector);
            int layoutSize = layout.size();
            int firstAny = -1;
            String tagging = enforceExplicitTagging(runtime, definition, collector);
            
            for (int i=0; i < layoutSize; ++i) {
                HashAdapter currentDefinition = new HashAdapter((RubyHash) layout.get(i));
                collector.clear();
                IRubyObject codec = ((IRubyObject) currentDefinition.get(RubyTemplate.CODEC));
                
                if (codec == RubyTemplate.CODEC_ANY && firstAny == -1)
                    firstAny = i;
                
                HashAdapter options = currentDefinition.getHash(RubyTemplate.OPTIONS); 
                Definition d = new Definition(currentDefinition, options);
                ParseStrategy s = d.accept(ctx, CodecStrategyVisitor.INSTANCE);
                MatchContext innerCtx = mctx.createTemporary(d);
                if (!successfullySkipHeaderIfExplicit(tagging, innerCtx))
                    return MatchResult.NO_MATCH;
                
                try {
                    ParseStrategy.MatchResult mr = s.match(innerCtx);
                    switch (mr) {
                    case MATCHED:
                        definition.setMatchedIndex(i);
                        return MatchResult.MATCHED;
                    case MATCHED_BY_DEFAULT: 
                        throw collector.addAndReturn(Errors.newASN1Error(runtime, "Inner CHOICE definition cannot have default values"));
                    default:
                        break;
                    }
                } catch (RaiseException ex) {
                    //ignore
                }
            }
            
            if (firstAny != -1) {
                definition.setMatchedIndex(firstAny);
                return MatchResult.MATCHED;
            }
            
            if (!definition.isOptional(ctx)) {
                throw collector.addAndReturn(Errors.newASN1Error(runtime, "Mandatory CHOICE value not found"));
            }
            
            return MatchResult.NO_MATCH;
        }
        
        private String enforceExplicitTagging(Ruby runtime, Definition definition, ErrorCollector collector) {
            String tagging = definition.getTagging().orNull();
            if (!(tagging == null || tagging.equals("EXPLICIT"))) {
                throw collector.addAndReturn(Errors.newASN1Error(runtime, "Only explicit tagging is allowed for CHOICEs"));
            }
            return tagging;
        }
        
        private boolean successfullySkipHeaderIfExplicit(String tagging, MatchContext mctx) {
            if (tagging != null) {
                try {
                    mctx.nextHeader();
                } catch (RuntimeException ex) {
                    return false;
                }
            }
            return true;
        }

        @Override
        public void parse(ParseContext pctx) {
            ThreadContext ctx = pctx.getCtx();
            Ruby runtime = ctx.getRuntime();
            ErrorCollector collector = pctx.getCollector();
            Definition definition = pctx.getDefinition();
            IRubyObject recv = pctx.getReceiver();
            Asn1Template template = pctx.getTemplate();
            RubyArray layout = definition.getLayout()
                               .orCollectAndThrow(Errors.newASN1Error(runtime, "Constructive type misses 'layout' definition"), collector);
            int matchedIndex = definition.getMatchedIndex();
            InstanceVariables ivs = recv.getInstanceVariables();
            
            HashAdapter matchedDef = new HashAdapter((RubyHash) layout.get(matchedIndex));
            HashAdapter matchedOpts = matchedDef.getHash(RubyTemplate.OPTIONS);
            HashAdapter oldDef = definition.getDefinition();
            HashAdapter oldOptions = definition.getOptions();
            
            if (enforceExplicitTagging(runtime, definition, collector) != null)
                template = nextTemplate(new ByteArrayInputStream(template.getObject().getValue()));
            
            template.setDefinition(matchedDef);
            template.setOptions(matchedOpts);
            Definition d = new Definition(matchedDef, matchedOpts);
            ParseContext innerCtx = new ParseContext(ctx, recv, template, d, collector);
            d.accept(ctx, CodecStrategyVisitor.INSTANCE).parse(innerCtx);
            
            RubyAsn1Template v = (RubyAsn1Template) ivs.getInstanceVariable("value");
            Asn1Template choiceTemplate = new Asn1Template(null, oldDef, oldOptions);
            choiceTemplate.setMatchedLayoutIndex(matchedIndex);
            choiceTemplate.setValue(v);
            choiceTemplate.setParsed(true);
            choiceTemplate.setDecoded(true);
            
            IRubyObject type = d.getTypeAsObject(ctx)
                                .orCollectAndThrow(Errors.newASN1Error(runtime, "'type' missing in inner choice definition"), collector);
            IRubyObject tag = RubyNumeric.int2fix(runtime, template.getObject().getHeader().getTag().getTag());
            ((RubyAsn1Template) recv).setTemplate(choiceTemplate);
            ivs.setInstanceVariable("type", type);
            ivs.setInstanceVariable("tag", tag);
        }

        @Override
        public void decode(ParseContext ctx) { /* NO OP */ }
    };
    
    private static byte[] skipExplicitHeader(Asn1Object object) {
        byte[] old = object.getValue();
        Header h = PARSER.next(new ByteArrayInputStream(old));
        int headerLen = h.getHeaderLength();
        int newLen = old.length - headerLen;
        byte[] bytes = new byte[newLen];
        System.arraycopy(old, headerLen, bytes, 0, newLen);
        return bytes;
    }
    
    private static String determineName(String name) {
        if (name != null)
            return name.substring(1);
        else
            return "value";
    }
    
    private static void setDefaultValue(MatchContext mctx) {
        ThreadContext ctx = mctx.getCtx();
        Ruby runtime = ctx.getRuntime();
        Definition definition = mctx.getDefinition();
        IRubyObject defaultValue = definition.getDefault(ctx).orThrow();
        String name = determineName(definition.getName().orNull());
        Asn1Template newTemplate = new Asn1Template(null, definition.getDefinition(), definition.getOptions());
        newTemplate.setValue(defaultValue);
        newTemplate.setParsed(true);
        newTemplate.setDecoded(true);
        
        mctx.getReceiver()
            .getInstanceVariables()
            .setInstanceVariable(name, new RubyAsn1Template(runtime, newTemplate));
    }
    
    private static boolean tryMatchConstructed(MatchContext mctx, int defaultTag) {
        ThreadContext ctx = mctx.getCtx();
        ErrorCollector collector = mctx.getCollector();
        Definition definition = mctx.getDefinition();
        Integer tag = definition.getTagAsInteger().orNull();
        String tagging = definition.getTagging().orNull();
        Header h = mctx.getHeader();
        
        if (!h.getTag().isConstructed()) {
            if (!definition.isOptional(ctx))
                throw collector.addAndReturn(Errors.newASN1Error(ctx.getRuntime(), "Mandatory sequence value not found"));
            return false;
        }
        if (Matcher.matchTagAndClass(ctx, h, tag, tagging, defaultTag))
            return true;
        
        if (!definition.isOptional(ctx)) 
                throw collector.addAndReturn(Matcher.tagMismatch(ctx, h, tag, tagging, defaultTag, "Constructive"));
        return false;
    }
    
    private static MatchResult checkOptionalOrDefault(MatchContext mctx, int defaultTag) {
        ThreadContext ctx = mctx.getCtx();
        Definition definition = mctx.getDefinition();
        ErrorCollector collector = mctx.getCollector();
        Integer tag = definition.getTagAsInteger().orNull();
        String tagging = definition.getTagging().orNull();
        String name = determineName(definition.getName().orNull());
            
        if (!definition.isOptional(ctx))
            throw collector.addAndReturn(Matcher.tagMismatch(ctx, mctx.getHeader(), tag, tagging, defaultTag, name));

        if (definition.hasDefault(ctx)) { 
            setDefaultValue(mctx);
            return MatchResult.MATCHED_BY_DEFAULT;
        }
        return MatchResult.NO_MATCH;
    }
    
    private static void parseAndAssign(ParseContext pctx) {
        ThreadContext ctx = pctx.getCtx();
        Definition definition = pctx.getDefinition();
        Ruby runtime = ctx.getRuntime();
        String name = determineName(definition.getName().orNull());
        Asn1Template template = pctx.getTemplate();
        pctx.getReceiver()
            .getInstanceVariables()
            .setInstanceVariable(name, new RubyAsn1Template(runtime, template));
        template.setParsed(true);
        template.setDecoded(false);
    }
    
}
