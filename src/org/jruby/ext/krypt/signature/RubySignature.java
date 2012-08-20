
package org.jruby.ext.krypt.signature;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;

/**
 *
 * @author Vipul A M <vipulnsward@gmail.com>
 */
public class RubySignature extends RubyObject {
    
    protected RubySignature(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }
     
    public static void createSignature(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyModule mSig = krypt.defineModuleUnder("Signature");
        RubyClass sigErr=mSig.defineClassUnder("SignatureError", kryptError, kryptError.getAllocator());
        RubyDSA.createDSA(runtime, mSig, sigErr);
        RubyRSA.createRSA(runtime, mSig, sigErr);
    }
}
