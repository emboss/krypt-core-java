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

import impl.krypt.asn1.ParseException;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.ParserFactory;
import java.io.InputStream;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.Streams;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class RubyParser extends RubyObject {
    
    private static ObjectAllocator PARSER_ALLOCATOR = new ObjectAllocator() {
        @Override
        public IRubyObject allocate(Ruby runtime, RubyClass type) {
            return new RubyParser(runtime, type);
        }
    };
    
    private static RubyClass cHeader;
    
    public static void createParser(Ruby runtime, RubyModule mASN1) {
        mASN1.defineClassUnder("Parser", runtime.getObject(), PARSER_ALLOCATOR)
             .defineAnnotatedMethods(RubyParser.class);
        cHeader = ((RubyModule)runtime.getModule("Krypt")
                                           .getConstant("ASN1"))
                                           .getClass("Header");
    }
    
    private final impl.krypt.asn1.Parser parser;
    
    public RubyParser(Ruby runtime, RubyClass type) {
        super(runtime, type);
        
        this.parser = new ParserFactory().newHeaderParser();
    }
    
    @Override
    @JRubyMethod()
    public IRubyObject initialize(ThreadContext ctx) {
        return this;
    }
    
    @JRubyMethod()
    public IRubyObject next(ThreadContext ctx, IRubyObject io) {
        Ruby runtime = ctx.getRuntime();
        InputStream in = asStream(runtime, io);
        return parseHeader(runtime, cHeader, in);
    }
    
    private IRubyObject parseHeader(Ruby runtime, RubyClass headerClass, InputStream in) {
        try {
            ParsedHeader h = parser.next(in);
            if (h == null) {
                return runtime.getNil();
            }
            else {
                return new RubyHeader(runtime, headerClass, h);
            }
        } 
        catch (ParseException ex) {
            throw Errors.newParseError(runtime, ex.getMessage());
        }
    }
    
    private static InputStream asStream(Ruby runtime, IRubyObject obj) {
        if (!obj.respondsTo("read"))
            throw Errors.newError(runtime, "ArgumentError", "Object must respond to read");
        return Streams.tryWrapAsInputStream(runtime, obj);
    }
}
