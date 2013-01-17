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
package org.jruby.ext.krypt.digest;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.Hex;
import org.jruby.ext.krypt.provider.Digest;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class RubyNativeDigest extends RubyObject {
    
    private static RubyClass cNativeDigest;
    
    public RubyNativeDigest(Ruby runtime, Digest digest) {
        super(runtime, cNativeDigest);
        this.digest = digest;
    }
        
    private Digest digest;
    
    @JRubyMethod
    public IRubyObject reset(ThreadContext ctx) {
        this.digest.reset();
        return this;
    }
    
    @JRubyMethod(name={"update","<<"})
    public IRubyObject update(ThreadContext ctx, IRubyObject data) {
        try {
            byte[] bytes = data.asString().getBytes();
            this.digest.update(bytes, 0, bytes.length);
            return this;
        } catch (Exception ex) {
            throw Errors.newDigestError(ctx.getRuntime(), "Error while updating digest: " + ex.getMessage());
        }
    }
    
    @JRubyMethod(optional=1)
    public IRubyObject digest(ThreadContext ctx, IRubyObject[] args) {
        Ruby runtime = ctx.getRuntime();
        if (args.length == 0)
            return digestFinalize(runtime);
        else
            return digestData(runtime, args[0]);
    }
    
    @JRubyMethod(optional=1)
    public IRubyObject hexdigest(ThreadContext ctx, IRubyObject[] args) {
        IRubyObject result = digest(ctx, args);
        return ctx.getRuntime().newString(Hex.encodeAsString(result.asString().getBytes()));
    }
    
    @JRubyMethod
    public IRubyObject name(ThreadContext ctx) {
        return ctx.getRuntime().newString(this.digest.getName());
    }
    
    @JRubyMethod
    public IRubyObject digest_length(ThreadContext ctx) {
        return RubyNumeric.int2fix(ctx.getRuntime(), this.digest.getDigestLength());
    }
    
    @JRubyMethod
    public IRubyObject block_length(ThreadContext ctx) {
        return RubyNumeric.int2fix(ctx.getRuntime(), this.digest.getBlockLength());
    }
    
    private IRubyObject digestFinalize(Ruby runtime) {
        try {
            byte[] result = digest.digest();
            return runtime.newString(new ByteList(result, false));
        } catch (Exception ex) {
            throw Errors.newDigestError(runtime, "Error while finalizing digest: " + ex.getMessage());
        }
    }
    
    private IRubyObject digestData(Ruby runtime, IRubyObject rbdata) {
        try {
            byte[] data = rbdata.asString().getBytes();
            byte[] result = digest.digest(data);
            return runtime.newString(new ByteList(result, false));
        } catch (Exception ex) {
            throw Errors.newDigestError(runtime, "Error while computing digest: " + ex.getMessage());
        }
    }
    
    public static void createDigest(Ruby runtime, RubyModule krypt) {
        RubyModule mDigest = (RubyModule)krypt.getConstant("Digest");
        cNativeDigest = mDigest.defineClassUnder("NativeDigest", runtime.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);
        cNativeDigest.defineAnnotatedMethods(RubyNativeDigest.class);
    }
}
