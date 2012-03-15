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
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class TemplateParser {
    
    private TemplateParser() {}
    
    static final impl.krypt.asn1.Parser PARSER = new ParserFactory().newHeaderParser();
    
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
        HashAdapter o = d.getHash(RubyTemplate.OPTIONS);
        Asn1Template template = new Asn1Template(h.getObject(), d, o);
        return new RubyAsn1Template(runtime, type, template);
    }
    
    protected static class ParseContext {
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
    
    protected interface ParseStrategy {
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
            recv.getInstanceVariables().setInstanceVariable(name.substring(1), new RubyAsn1Template(runtime, RubyTemplate.cTemplateValue, newTemplate));
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
            current.setOptions(currentDefinition.getHash(RubyTemplate.OPTIONS));
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
            Definition definition = new Definition(currentDefinition, currentDefinition.getHash(RubyTemplate.OPTIONS));
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
    
}
