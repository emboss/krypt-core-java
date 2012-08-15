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
import org.jruby.exceptions.RaiseException;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Errors {
   
    private Errors() { }
    
    public static RaiseException newParseError(Ruby rt, String message) {
        return newError(rt, "Krypt::ASN1::ParseError", message);
    }
    
    public static RaiseException newSerializeError(Ruby rt, String message) {
        return newError(rt, "Krypt::ASN1::SerializeError", message);
    }
    
    public static RaiseException newASN1Error(Ruby rt, String message) {
        return newError(rt, "Krypt::ASN1::ASN1Error", message);
    }
    
    public static RaiseException newPEMError(Ruby rt, String message) {
        return newError(rt, "Krypt::PEM::PEMError", message);
    }
    
    public static RaiseException newHexError(Ruby rt, String message) {
        return newError(rt, "Krypt::Hex::HexError", message);
    }
    
    public static RaiseException newBase64Error(Ruby rt, String message) {
        return newError(rt, "Krypt::Base64::Base64Error", message);
    }
    
    public static RaiseException newDigestError(Ruby rt, String message) {
        return newError(rt, "Krypt::Digest::DigestError", message);
    }
    
    public static RaiseException newCipherError(Ruby rt, String message) {
        return newError(rt, "Krypt::Cipher::CipherError", message);
    }
    
    public static RaiseException newSignatureError(Ruby rt, String message) {
        return newError(rt, "Krypt::SignatureError::DSAError", message);
    }
    
    public static RaiseException newError(Ruby rt, String path, String message) {
        return new RaiseException(rt, getClassFromPath(rt, path), message, true);
    }
    
    public static RubyClass getClassFromPath(Ruby rt, String path) {
        return (RubyClass)rt.getClassFromPath(path);
    }
}
