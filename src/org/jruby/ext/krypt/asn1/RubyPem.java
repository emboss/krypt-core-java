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

import impl.krypt.asn1.pem.PemInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.Streams;
import org.jruby.runtime.Block;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class RubyPem {
    
    private RubyPem() {}
    
    private static void yieldToBlock(ThreadContext ctx, IRubyObject current, String jname, int ji, Block block) {
        IRubyObject name = ctx.getRuntime().newString(jname);
        IRubyObject i = RubyNumeric.int2fix(ctx.getRuntime(), ji);
        block.yieldSpecific(ctx, current, name, i);
    }
    
    private static IRubyObject decodeAry(ThreadContext ctx, PemInputStream pem, Block block) throws IOException {
        Ruby runtime = ctx.getRuntime();
        List<IRubyObject> ary = new ArrayList<IRubyObject>();
        byte[] bytes;
        int i = 0;
        
        while ((bytes = Streams.consume(pem)) != null) {
            IRubyObject current = runtime.newString(new ByteList(bytes, false));
            if (block.isGiven()) {
               yieldToBlock(ctx, current, pem.getCurrentName(), i, block);
            }
            i++;
            ary.add(current);
            pem.continueStream();
        }
        
        return runtime.newArray(ary);
    }
            
    @JRubyMethod(meta = true)
    public static IRubyObject decode(ThreadContext ctx, IRubyObject recv, IRubyObject value, Block block) {
        try {
            Ruby rt = ctx.getRuntime();
            InputStream in;
            if (value.respondsTo("read")) {
                in = Streams.tryWrapAsInputStream(rt, value);
            } else {
                in = new ByteArrayInputStream(toPemIfPossible(value).convertToString().getBytes());
            }
            PemInputStream pemin = new PemInputStream(in);
            return decodeAry(ctx, pemin, block);
        } catch(Exception e) {
            throw Errors.newPEMError(ctx.getRuntime(), e.getMessage());
        }
    }
    
    public static IRubyObject toPem(IRubyObject obj) {
        return obj.callMethod(obj.getRuntime().getCurrentContext(), "to_pem");
    }

    public static IRubyObject toPemIfPossible(IRubyObject asn1) {
        if(asn1.respondsTo("to_pem")) {
            return toPem(asn1);
        } else {
            return asn1;
        }
    }
    
    public static void createPem(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyModule mPEM = runtime.defineModuleUnder("PEM", krypt);
        mPEM.defineClassUnder("PEMError", kryptError, kryptError.getAllocator());
        mPEM.defineAnnotatedMethods(RubyPem.class);
    }
    
}
