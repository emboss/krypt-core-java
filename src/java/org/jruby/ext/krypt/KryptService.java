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
package org.jruby.ext.krypt;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.ext.krypt.asn1.Parser;
import org.jruby.runtime.ObjectAllocator;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class KryptService {
    
    public static void create(Ruby runtime) {
        RubyModule krypt = runtime.getOrCreateModule("Krypt");
        RubyClass standardError = runtime.getClass("StandardError");
        RubyClass kryptError = krypt.defineClassUnder("KryptError", standardError, standardError.getAllocator());
        createAsn1(runtime, krypt, kryptError);
    }
    
    private static void createAsn1(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyModule mAsn1 = runtime.defineModuleUnder("Asn1", krypt);
        
        RubyClass asn1Error = mAsn1.defineClassUnder("Asn1Error", kryptError, kryptError.getAllocator());
        mAsn1.defineClassUnder("ParseError", asn1Error, asn1Error.getAllocator());
        mAsn1.defineClassUnder("SerializeError", asn1Error, asn1Error.getAllocator());
        
        Parser.createParser(runtime, mAsn1);
    }
    
}
