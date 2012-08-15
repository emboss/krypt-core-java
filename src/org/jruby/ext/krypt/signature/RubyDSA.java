
package org.jruby.ext.krypt.signature;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
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
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 *
 * @author Vipul A M <vipulnsward@gmail.com>
 */
public class RubyDSA extends RubyObject{
    
    private Signature sig;
    private KeyPair pair;
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
    public RubyString getName(ThreadContext ctx) {
        return RubyString.newString(ctx.getRuntime(), sig.getAlgorithm());
    }    
    
     
    @JRubyMethod
    public IRubyObject initialize(ThreadContext ctx, IRubyObject rbDigest) throws NoSuchAlgorithmException, InvalidKeyException {
        Ruby runtime = ctx.getRuntime();
        if (!(rbDigest instanceof RubyDigest))  getRuntime().newArgumentError(" digest object expected");
        RubyDigest dig = (RubyDigest) rbDigest;
        String digName=dig.getName();
        
        /* 
         * STUB!!!
         * Generate a key pair
         * This need to be modularized to RubyKey Internally 
         * and Amends for Keystore 
         */
 
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(1024, random);
        pair = keyGen.generateKeyPair();

        PublicKey pub=pair.getPublic();
        PrivateKey priv= pair.getPrivate(); 
        name=digName+"withDSA";
        sig = Signature.getInstance(name); 
        sig.initSign(priv);
        
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
    
    public void checkVerify(Ruby rt){
        try {
            sig.initVerify(pair.getPublic());
        } catch (InvalidKeyException ex) {
           Errors.newSignatureError(rt, " could not initialize verification");
        }
    }
    
    @JRubyMethod
    public RubyBoolean verify(ThreadContext ctx, IRubyObject sbytes){
        checkVerify(ctx.getRuntime());
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
