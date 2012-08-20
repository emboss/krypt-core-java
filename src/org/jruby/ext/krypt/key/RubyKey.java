
package org.jruby.ext.krypt.key;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;

/**
 *
 * @author Vipul A M <vipulnsward@gmail.com>
 */
public class RubyKey extends RubyObject {
    
    protected RubyKey(Ruby runtime, RubyClass type) {
        super(runtime, type);
    }
     
    public static void createKey(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyModule mKey = krypt.defineModuleUnder("Key");
        RubyClass keyErr=mKey.defineClassUnder("KeyError", kryptError, kryptError.getAllocator());
        RubyDSAPrivateKey.createKey(runtime, mKey, keyErr);
        RubyDSAPublicKey.createKey(runtime, mKey, keyErr);
        RubyRSAPrivateKey.createKey(runtime, mKey, keyErr);
        RubyRSAPublicKey.createKey(runtime, mKey, keyErr);
    }
}
