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
* Copyright (C) 2011-2013
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <Martin.Bosslet@gmail.com>
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
