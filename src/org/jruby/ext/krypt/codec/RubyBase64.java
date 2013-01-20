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
package org.jruby.ext.krypt.codec;

import java.io.IOException;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Base64;
import org.jruby.ext.krypt.Errors;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class RubyBase64 {
    
    private RubyBase64() {}
    
    @JRubyMethod(meta = true, required=1, optional=1)
    public static IRubyObject encode(ThreadContext ctx, IRubyObject recv, IRubyObject[] args) {
        try {
            byte[] bytes = args[0].convertToString().getBytes();
            int cols;
            if (args.length == 2) {
                cols = RubyNumeric.num2int(args[1]);
            } else {
                cols = -1;
            }
            byte[] encoded = Base64.encode(bytes, cols);
            return RubyString.newUsAsciiStringNoCopy(ctx.getRuntime(), new ByteList(encoded, false));
        } catch (IOException ex) {
            throw Errors.newBase64Error(ctx.getRuntime(), ex.getMessage());
        } catch (RuntimeException ex) {
            throw Errors.newBase64Error(ctx.getRuntime(), ex.getMessage());
        }
    }
    
    @JRubyMethod(meta = true)
    public static IRubyObject decode(ThreadContext ctx, IRubyObject recv, IRubyObject data) {
        try {
            byte[] bytes = data.convertToString().getBytes();
            byte[] decoded = Base64.decode(bytes);
            return ctx.getRuntime().newString(new ByteList(decoded, false));
        } catch (IOException ex) {
            throw Errors.newBase64Error(ctx.getRuntime(), ex.getMessage());
        } catch (RuntimeException ex) {
            throw Errors.newBase64Error(ctx.getRuntime(), ex.getMessage());
        }
    }
    
    public static void createBase64(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyModule mBase64 = runtime.defineModuleUnder("Base64", krypt);
        mBase64.defineClassUnder("Base64Error", kryptError, kryptError.getAllocator());
        mBase64.defineAnnotatedMethods(RubyBase64.class);
    }
        
}
