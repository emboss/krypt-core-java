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

import impl.krypt.asn1.Length;
import impl.krypt.asn1.ParseException;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.SerializeException;
import impl.krypt.asn1.Tag;
import impl.krypt.asn1.TagClass;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import org.jruby.Ruby;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyEncoding;
import org.jruby.RubyIO;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.Streams;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class RubyHeader extends RubyObject {
    
    public static void createHeader(Ruby runtime, RubyModule mASN1) {
        mASN1.defineClassUnder("Header", runtime.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR)
             .defineAnnotatedMethods(RubyHeader.class);
    }
    
    private final ParsedHeader h;
    
    private final IRubyObject tag;
    private final IRubyObject tagClass;
    private final IRubyObject isConstructed;
    private final IRubyObject isInfLen;
    private final IRubyObject len;
    private final IRubyObject hlen;
    
    private IRubyObject cachedValue;
    
    public RubyHeader(Ruby runtime, RubyClass type, impl.krypt.asn1.ParsedHeader h) {
        super(runtime, type);
        if (h == null) throw new NullPointerException();
    
        this.h = h;
        
        Tag t = h.getTag();
        Length l = h.getLength();
        this.tag = runtime.newFixnum(t.getTag());
        this.tagClass = tagClassFor(runtime, t.getTagClass());
        this.isConstructed = runtime.newBoolean(t.isConstructed());
        this.isInfLen = runtime.newBoolean(l.isInfiniteLength());
        this.len = runtime.newFixnum(l.getLength());
        this.hlen = runtime.newFixnum(h.getHeaderLength());
    }
    
    static IRubyObject tagClassFor(Ruby runtime, TagClass tc) {
        switch(tc) {
            case UNIVERSAL:
                return RubySymbol.newSymbol(runtime, TagClass.UNIVERSAL.name());
            case CONTEXT_SPECIFIC:
                return RubySymbol.newSymbol(runtime, TagClass.CONTEXT_SPECIFIC.name());
            case APPLICATION:
                return RubySymbol.newSymbol(runtime, TagClass.APPLICATION.name());
            case PRIVATE:
                return RubySymbol.newSymbol(runtime, TagClass.PRIVATE.name());
            default:
                throw runtime.newRuntimeError("Unkown TagClass " + tc);
        }
    }
    
    @JRubyMethod
    public IRubyObject tag() {
        return tag;
    }
    
    @JRubyMethod
    public IRubyObject tag_class() {
        return tagClass;
    }
    
    @JRubyMethod(name="constructed?")
    public IRubyObject is_constructed() {
        return isConstructed;
    }
    
    @JRubyMethod(name="infinite?")
    public IRubyObject is_infinite() {
        return isInfLen;
    }
    
    @JRubyMethod(name={"size","length"})
    public IRubyObject size() {
        return len;
    }
    
    @JRubyMethod(name={"header_size","header_length"})
    public IRubyObject header_size() {
        return hlen;
    }
    
    @JRubyMethod
    public IRubyObject encode_to(ThreadContext ctx, IRubyObject io) {
        Ruby runtime = ctx.getRuntime();
        OutputStream out = Streams.tryWrapAsOuputStream(runtime, io);
        try {
            h.encodeTo(out);
            return this;
        }
        catch (SerializeException ex) {
            throw Errors.newSerializeError(runtime, ex.getMessage());
        }
    }
    
    @JRubyMethod
    public IRubyObject bytes(ThreadContext ctx) {
        Ruby runtime = ctx.getRuntime();
        
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            h.encodeTo(baos);
            return runtime.newString(new ByteList(baos.toByteArray(), false));
        }
        catch (SerializeException ex) {
            throw Errors.newSerializeError(runtime, ex.getMessage());
        }
    }
    
    @JRubyMethod
    public synchronized IRubyObject skip_value() {
        h.skipValue();
        return this;
    }
    
    @JRubyMethod
    public synchronized IRubyObject value(ThreadContext ctx) {
        if (cachedValue == null) {
            cachedValue = readValue(ctx);
        }
        return cachedValue;
    }
    
    private IRubyObject readValue(ThreadContext ctx) {
        Ruby runtime = ctx.getRuntime();
        
        try {
            byte[] value = h.getValue();
            if (value == null || value.length == 0)
                return runtime.getNil();
            else
                return runtime.newString(new ByteList(value, false));
        }
        catch (ParseException ex) {
            throw Errors.newParseError(runtime, ex.getMessage());
        }
    }
    
    @JRubyMethod(optional=1)
    public synchronized IRubyObject value_io(ThreadContext ctx, IRubyObject[] args) {
        Ruby runtime = ctx.getRuntime();
        IRubyObject valuesOnly = args.length > 0 ? args[0] : RubyBoolean.newBoolean(runtime, true);
        try {
            InputStream valueStream = h.getValueStream(valuesOnly.isTrue());
            RubyIO io = new RubyIO(runtime, valueStream);
            IRubyObject binaryEncoding = RubyEncoding.newEncoding(runtime, 
                                         runtime.getEncodingService().getAscii8bitEncoding());
            io.set_encoding(ctx, binaryEncoding);
            return io;
        } 
        catch (ParseException ex) {
            throw Errors.newParseError(runtime, ex.getMessage());
        }
    }
    
    @JRubyMethod
    public IRubyObject to_s(ThreadContext ctx) {
        Tag t = h.getTag();
        Length l = h.getLength();
        String s = new StringBuilder()
                .append("Tag: ").append(t.getTag())
                .append(" Tag Class: ").append(t.getTagClass().name())
                .append(" Length: ").append(l.getLength())
                .append(" Header Length: ").append(h.getHeaderLength())
                .append(" Constructed: ").append(t.isConstructed())
                .append(" Infinite Length: ").append(l.isInfiniteLength())
                .toString();
        return ctx.getRuntime().newString(s);
    }
}
