/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
package org.jruby.ext.krypt.helper;

import org.jruby.Ruby;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class RubyHelper {

    private RubyHelper() {}
    
    public static class RubyString {
    
        @JRubyMethod(meta = true)
        public static IRubyObject buffer(ThreadContext ctx, IRubyObject recv, IRubyObject size) {
            return ctx.getRuntime().newString(new ByteList(new byte[RubyNumeric.num2int(size)], false));
        }
        
        @JRubyMethod(meta = true)
        public static IRubyObject xor(ThreadContext ctx, IRubyObject recv, IRubyObject s1, IRubyObject s2) {
            ByteList tmp1 = s1.asString().getByteList();
            ByteList tmp2 = s2.asString().getByteList();
            byte[] src1 = tmp1.getUnsafeBytes();
            byte[] src2 = tmp2.getUnsafeBytes();
            
            int begin1 = tmp1.getBegin();
            int end1 = tmp1.getRealSize();
            int begin2 = tmp2.getBegin();
            int end2 = tmp2.getRealSize();
            int len = end1 - begin1;
            
            if ((end2 - begin2) != len)
                throw Errors.newKryptError(ctx.getRuntime(), "String sizes don't match");
            
            byte[] target = new byte[len];
            
            for (int i=0; i < len; i++) {
                target[i] = (byte)(src1[begin1 + i] ^ src2[begin2 + i]);
            }
            
            return ctx.getRuntime().newString(new ByteList(target, false));
        }
        
        @JRubyMethod(meta = true, name={"xor!"})
        public static IRubyObject xor_bang(ThreadContext ctx, IRubyObject recv, IRubyObject s1, IRubyObject s2) {
            ByteList target = s1.asString().getByteList();
            ByteList tmp = s2.asString().getByteList();
            byte[] src = tmp.getUnsafeBytes();
            
            int begin = tmp.getBegin();
            int end = tmp.getRealSize();
            int len = end - begin;
            
            if ((target.getRealSize() - target.getBegin()) != len)
                throw Errors.newKryptError(ctx.getRuntime(), "String sizes don't match");
            
            for (int i=0; i < end; i++) {
                target.set(i, target.get(i) ^ src[begin + i]);
            }

            return s1;
        }
    }
    
    public static void createHelper(Ruby runtime, RubyModule krypt) {
        RubyModule mHelper = runtime.defineModuleUnder("Helper", krypt);
        RubyModule mString = runtime.defineModuleUnder("String", mHelper);
        mString.defineAnnotatedMethods(RubyString.class);
    }
}
