package org.jruby.ext.krypt.key;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
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
public class RubyECPrivateKey extends RubyObject {

    private ECPrivateKey pkey;

    protected RubyECPrivateKey(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }
    
    public static void createKey(Ruby runtime, RubyModule mKey, RubyClass keyError) {
        RubyModule mPrivKey = mKey.defineModuleUnder("ECPrivateKey");
        mPrivKey.defineAnnotatedMethods(RubyECPrivateKey.class);
    }

    @JRubyMethod
    public IRubyObject initialize(ThreadContext ctx, IRubyObject keyData) {
        try {
            getPrivateKeyFromBytes(keyData.asJavaString().getBytes());
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
    
    private void getPrivateKeyFromBytes(byte[] privateKeyObject) throws GeneralSecurityException {
        KeyFactory fac = KeyFactory.getInstance("EC");
        EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privateKeyObject);
        pkey= (ECPrivateKey) fac.generatePrivate(privKeySpec);
    }
    
    public ECPrivateKey getKey(){
        return pkey;
    }

}
