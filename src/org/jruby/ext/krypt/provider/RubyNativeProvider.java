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
package org.jruby.ext.krypt.provider;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.digest.RubyNativeDigest;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class RubyNativeProvider extends RubyObject {
    
    private static RubyClass cNativeProvider;
    private static RubyModule mDigest;
    
    public static void createProvider(Ruby runtime, RubyModule mKrypt) {
        RubyModule mProvider = (RubyModule)mKrypt.getConstant("Provider");
        cNativeProvider = mProvider.defineClassUnder("NativeProvider", runtime.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);
        cNativeProvider.defineAnnotatedMethods(RubyNativeProvider.class);
        mDigest = (RubyModule)mKrypt.getConstant("Digest");
    }
    
    public static RubyClass getRubyClass() {
        return cNativeProvider;
    }
    
    private final KryptProvider provider;
    
    protected RubyNativeProvider(Ruby runtime, RubyClass type, KryptProvider provider) {
        super(runtime, type);
        if (provider == null) throw new NullPointerException();
    
        this.provider = provider;
    }
    
    @JRubyMethod
    public IRubyObject name(ThreadContext ctx) {
        return ctx.getRuntime().newString(provider.getName());
    }
    
    @JRubyMethod(required = 1, rest = true)
    public IRubyObject new_service(ThreadContext ctx, IRubyObject[] args) {
        IRubyObject serviceClass = args[0];
        
        if (serviceClass == mDigest) {
            return newDigest(ctx, stripFirst(args));
        }
        
        return ctx.getRuntime().getNil();
    }
    
    @JRubyMethod
    public IRubyObject finalize(ThreadContext ctx) {
        /* do nothing */
        provider.cleanUp();
        return ctx.getRuntime().getNil();
    }
    
    private IRubyObject newDigest(ThreadContext ctx, IRubyObject[] args) {
        Ruby runtime = ctx.getRuntime();
        if (args == null) return runtime.getNil();
        String nameOrOid = args[0].convertToString().asJavaString();
        Digest digest = provider.newDigestByName(nameOrOid);
        if (digest == null)
            digest = provider.newDigestByOid(nameOrOid);
        if (digest == null)
            return runtime.getNil();
        else
            return new RubyNativeDigest(runtime, digest);
    }
    
    private static IRubyObject[] stripFirst(IRubyObject[] args) {
        if (args.length == 1)
            return null;
        
        IRubyObject[] ret = new IRubyObject[args.length - 1];
        for (int i=1; i < args.length; i++) {
            ret[i - 1] = args[i];
        }
        return ret;
    }
}
