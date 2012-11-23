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
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
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
