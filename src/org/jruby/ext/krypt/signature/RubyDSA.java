
package org.jruby.ext.krypt.signature;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import org.jruby.Ruby;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.digest.RubyDigest;
import org.jruby.ext.krypt.key.RubyDSAPrivateKey;
import org.jruby.ext.krypt.key.RubyDSAPublicKey;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 *
 * @author Vipul A M <vipulnsward@gmail.com>
 */
public class RubyDSA extends RubyObject{
    
    private Signature sig;
    private String name="";
    
    private static ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        @Override
        public IRubyObject allocate(Ruby runtime, RubyClass type) {
            return new RubyDSA(runtime, type);
        }
    };
    
    protected RubyDSA(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }
    
    public static void createDSA(Ruby runtime, RubyModule mSig, RubyClass sigError) {
        
        RubyClass cDSA = mSig.defineClassUnder("DSA", null, ALLOCATOR );;
        RubyClass dsaErr=mSig.defineClassUnder("DSAError", sigError, sigError.getAllocator());
        cDSA.defineAnnotatedMethods(RubyDSA.class);        
    }
    

    @JRubyMethod
    public RubyString name(ThreadContext ctx) {
        return RubyString.newString(ctx.getRuntime(), sig.getAlgorithm());
    }    
    
     
    @JRubyMethod
    public IRubyObject initialize(ThreadContext ctx, IRubyObject rbDigest) throws NoSuchAlgorithmException, InvalidKeyException {
        Ruby runtime = ctx.getRuntime();
        if (!(rbDigest instanceof RubyDigest))  getRuntime().newArgumentError(" digest object expected");
        RubyDigest dig = (RubyDigest) rbDigest;
        String digName=dig.getName();
        name=digName+"withDSA";
        sig = Signature.getInstance(name); 
        return this;
    }
    
    @JRubyMethod
    public IRubyObject update(ThreadContext ctx, IRubyObject rbytes){
        try {
            sig.update(rbytes.asJavaString().getBytes());
        } catch (SignatureException ex) {
            getRuntime().newArgumentError(" invalid bytes provided for update");
        }
        return this;
    }
    
    @JRubyMethod
    public IRubyObject sign(ThreadContext ctx){
        try {
            sig.sign();
        } catch (SignatureException ex) {
            getRuntime().newArgumentError(" invalid bytes provided for update");
        }
        return this;
    }

    
    @JRubyMethod
    public IRubyObject initv(ThreadContext ctx, IRubyObject key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
        if(key instanceof RubyDSAPublicKey){
          sig.initVerify(((RubyDSAPublicKey)key).getKey());
        } else{
        KeyFactory fac = KeyFactory.getInstance("DSA");
        EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(key.asJavaString().getBytes());
        sig.initVerify(fac.generatePublic(pubKeySpec));
        } 
        return this; 
    }
    
    @JRubyMethod
    public IRubyObject inits(ThreadContext ctx, IRubyObject key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
        if(key instanceof RubyDSAPrivateKey){
          sig.initSign(((RubyDSAPrivateKey)key).getKey());
        } else{
        KeyFactory fac = KeyFactory.getInstance("DSA");
        EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(key.asJavaString().getBytes());
        sig.initSign(fac.generatePrivate(privKeySpec));
        } 
        return this; 
    }
    
    @JRubyMethod
    public RubyBoolean verify(ThreadContext ctx, IRubyObject sbytes){
        try {
            return ((sig.verify(sbytes.asJavaString().getBytes())) ? RubyBoolean.newBoolean(ctx.getRuntime(), true) : RubyBoolean.newBoolean(ctx.getRuntime(), false)) ;
        } catch (SignatureException ex) {
             Errors.newSignatureError(ctx.getRuntime()," could not verify");
        } finally{
            return RubyBoolean.newBoolean(ctx.getRuntime(), false);
        }
    }
    
    @JRubyMethod
    public RubyBoolean verify(ThreadContext ctx, IRubyObject sbytes, IRubyObject off, IRubyObject len ){
        int offset = RubyNumeric.num2int(off);
        int length= RubyNumeric.num2int(len);
        try {
            return ((sig.verify(sbytes.asJavaString().getBytes(), offset, length)) ? RubyBoolean.newBoolean(ctx.getRuntime(), true) : RubyBoolean.newBoolean(ctx.getRuntime(), false)) ;
        } catch (SignatureException ex) {
             Errors.newSignatureError(ctx.getRuntime()," could not verify");
        } finally{
            return RubyBoolean.newBoolean(ctx.getRuntime(), false);
        }
    }
    
}
