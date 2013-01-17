/*
 * krypt-core API - Java version
 *
 * Copyright (c) 2011-2013
 * Hiroshi Nakamura <nahi@ruby-lang.org>
 * Martin Bosslet <martin.bosslet@gmail.com>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package org.jruby.ext.krypt;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.ext.krypt.asn1.RubyAsn1;
import org.jruby.ext.krypt.asn1.RubyPem;
import org.jruby.ext.krypt.codec.RubyHex;
import org.jruby.ext.krypt.digest.RubyNativeDigest;
import org.jruby.ext.krypt.provider.RubyNativeProvider;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class KryptCoreService {
    
    public static void create(Ruby runtime) {
        RubyModule krypt = runtime.getOrCreateModule("Krypt");
        RubyClass kryptError = krypt.getClass("Error");
        
        RubyAsn1.createAsn1(runtime, krypt, kryptError);
        RubyPem.createPem(runtime, krypt, kryptError);
        RubyHex.createHex(runtime, krypt, kryptError);
        
        RubyNativeDigest.createDigest(runtime, krypt);
        RubyNativeProvider.createProvider(runtime, krypt);
    }    
}
