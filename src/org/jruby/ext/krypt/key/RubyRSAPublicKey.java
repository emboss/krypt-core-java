
package org.jruby.ext.krypt.key;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 *
 * @author Vipul A M <vipulnsward@gmail.com>
 */
public class RubyRSAPublicKey extends RubyObject {

    private RSAPublicKey pkey;

    protected RubyRSAPublicKey(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }

    public static void createKey(Ruby runtime, RubyModule mKey, RubyClass keyError) {
        RubyModule mPubKey = mKey.defineModuleUnder("RSAPublicKey");
        mPubKey.defineAnnotatedMethods(RubyRSAPublicKey.class);
    }

        @JRubyMethod
    public IRubyObject initialize(ThreadContext ctx, IRubyObject keyData) {
        try {
            getPublicKeyFromBytes(keyData.asJavaString().getBytes());
        } catch (GeneralSecurityException ex) {
            Errors.newKeyError(ctx.getRuntime()," unable to create key from given data");
        }
        return this;
    }
    
    @JRubyMethod
    public IRubyObject encoded(ThreadContext ctx, IRubyObject keyData) {
        return RubyString.newString(ctx.getRuntime(), pkey.getEncoded());
    }
    
    @JRubyMethod
    public IRubyObject algorithm(ThreadContext ctx, IRubyObject keyData) {
        return RubyString.newString(ctx.getRuntime(), pkey.getAlgorithm());
    }
    
    private void getPublicKeyFromBytes(byte[] pubKeyObject) throws GeneralSecurityException {
        KeyFactory fac = KeyFactory.getInstance("RSA");
        EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(pubKeyObject);
        pkey= (RSAPublicKey) fac.generatePublic(pubKeySpec);
    }
    
    public RSAPublicKey getKey(){
        return pkey;
    }
}
