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

import java.security.NoSuchAlgorithmException;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.provider.Digest;
import org.jruby.ext.krypt.provider.KryptProvider;
import org.jruby.ext.krypt.provider.ProviderRegistry;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class RubyDigest extends RubyObject {
    
    private static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        @Override
        public IRubyObject allocate(Ruby runtime, RubyClass type) {
            return new RubyDigest(runtime, type);
        }
    };
        
    protected RubyDigest(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }
    
    protected RubyDigest(Ruby runtime, RubyClass type, Digest digest) {
        this(runtime, type);
        this.digest = digest;
    }
        
    private Digest digest;
    
    @JRubyMethod
    public IRubyObject initialize(ThreadContext ctx, IRubyObject rbtype) {
        Ruby runtime = ctx.getRuntime();
        KryptProvider defaultProvider = ProviderRegistry.getInstance().getDefaultProvider();
        String type = rbtype.asJavaString();
        try {
            this.digest = defaultProvider.newDigestByName(type);
        } catch (NoSuchAlgorithmException ex) {
            try {
                this.digest = defaultProvider.newDigestByOid(type);
            } catch (NoSuchAlgorithmException ex2) {
                throw Errors.newDigestError(runtime, "Unknown digest algorithm: " + type);
            }
        } catch (Exception ex) {
            throw Errors.newDigestError(runtime, ex.getMessage());
        }
        return this;
    }
    
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
    
    public static void createDigest(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyClass cDigest = krypt.defineClassUnder("Digest", runtime.getObject(), ALLOCATOR);
        cDigest.defineAnnotatedMethods(RubyDigest.class);
        cDigest.defineClassUnder("DigestError", kryptError, kryptError.getAllocator());
        RubyClass cSha1 = cDigest.defineClassUnder("SHA1", cDigest, Sha1.ALLOCATOR);
        cSha1.defineAnnotatedMethods(Sha1.class);
        RubyClass cSha224 = cDigest.defineClassUnder("SHA224", cDigest, Sha224.ALLOCATOR);
        cSha224.defineAnnotatedMethods(Sha224.class);
        RubyClass cSha256 = cDigest.defineClassUnder("SHA256", cDigest, Sha256.ALLOCATOR);
        cSha256.defineAnnotatedMethods(Sha256.class);
        RubyClass cSha384 = cDigest.defineClassUnder("SHA384", cDigest, Sha384.ALLOCATOR);
        cSha384.defineAnnotatedMethods(Sha384.class);
        RubyClass cSha512 = cDigest.defineClassUnder("SHA512", cDigest, Sha512.ALLOCATOR);
        cSha512.defineAnnotatedMethods(Sha512.class);
        RubyClass cRipemd160 = cDigest.defineClassUnder("RIPEMD160", cDigest, Ripemd160.ALLOCATOR);
        cRipemd160.defineAnnotatedMethods(Ripemd160.class);
        RubyClass cMD5 = cDigest.defineClassUnder("MD5", cDigest, MD5.ALLOCATOR);
        cMD5.defineAnnotatedMethods(MD5.class);
    }
    
    private static Digest newDigest(Ruby runtime, String algorithm) {
        try {
            return ProviderRegistry.getInstance().getDefaultProvider().newDigestByName(algorithm);
        } catch (NoSuchAlgorithmException ex) {
            throw Errors.newDigestError(runtime, "Unknown digest algorithm: " + algorithm);
        } catch (Exception ex) {
            throw Errors.newDigestError(runtime, ex.getMessage());
        }
    }
    
    public static class Sha1 extends RubyDigest {

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Sha1(runtime, type);
            }
        };
        
        public Sha1(Ruby runtime, RubyClass type) {
            super(runtime, type, newDigest(runtime, "SHA1"));
        }
        
        @JRubyMethod
        @Override
        public IRubyObject initialize(ThreadContext ctx) {
            return this;
        }
    }
    
    public static class Sha224 extends RubyDigest {

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Sha224(runtime, type);
            }
        };
        
        public Sha224(Ruby runtime, RubyClass type) {
            super(runtime, type, newDigest(runtime, "SHA224"));
        }
        
        @JRubyMethod
        @Override
        public IRubyObject initialize(ThreadContext ctx) {
            return this;
        }
    }
    
    public static class Sha256 extends RubyDigest {

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Sha256(runtime, type);
            }
        };
        
        public Sha256(Ruby runtime, RubyClass type) {
            super(runtime, type, newDigest(runtime, "SHA256"));
        }
        
        @JRubyMethod
        @Override
        public IRubyObject initialize(ThreadContext ctx) {
            return this;
        }
    }
    
    public static class Sha384 extends RubyDigest {

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Sha384(runtime, type);
            }
        };
        
        public Sha384(Ruby runtime, RubyClass type) {
            super(runtime, type, newDigest(runtime, "SHA384"));
        }
        
        @JRubyMethod
        @Override
        public IRubyObject initialize(ThreadContext ctx) {
            return this;
        }
    }
    
    public static class Sha512 extends RubyDigest {

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Sha512(runtime, type);
            }
        };
        
        public Sha512(Ruby runtime, RubyClass type) {
            super(runtime, type, newDigest(runtime, "SHA512"));
        }
        
        @JRubyMethod
        @Override
        public IRubyObject initialize(ThreadContext ctx) {
            return this;
        }
    }
    
    public static class Ripemd160 extends RubyDigest {

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new Ripemd160(runtime, type);
            }
        };
        
        public Ripemd160(Ruby runtime, RubyClass type) {
            super(runtime, type, newDigest(runtime, "RIPEMD160"));
        }
        
        @JRubyMethod
        @Override
        public IRubyObject initialize(ThreadContext ctx) {
            return this;
        }
    }
    
    public static class MD5 extends RubyDigest {

        static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
            @Override
            public IRubyObject allocate(Ruby runtime, RubyClass type) {
                return new MD5(runtime, type);
            }
        };
        
        public MD5(Ruby runtime, RubyClass type) {
            super(runtime, type, newDigest(runtime, "MD5"));
        }
        
        @JRubyMethod
        @Override
        public IRubyObject initialize(ThreadContext ctx) {
            return this;
        }
    }
}
