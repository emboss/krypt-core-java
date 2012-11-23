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
* Copyright (C) 2011 - 2012 
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
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
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
    
    private final KryptProvider provider;
    
    public RubyNativeProvider(Ruby runtime, KryptProvider provider) {
        super(runtime, cNativeProvider);
        if (provider == null) throw new NullPointerException();
    
        this.provider = provider;
    }
    
    @JRubyMethod(required = 1, rest = true)
    public IRubyObject new_service(ThreadContext ctx, IRubyObject[] args) {
        IRubyObject serviceClass = args[0];
        
        if (serviceClass == mDigest) {
            return newDigest(ctx, stripFirst(args));
        }
        
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
