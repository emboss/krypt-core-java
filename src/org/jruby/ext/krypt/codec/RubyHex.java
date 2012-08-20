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
package org.jruby.ext.krypt.codec;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.Hex;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class RubyHex {
    
    private RubyHex() {}
    
    @JRubyMethod(meta = true)
    public static IRubyObject encode(ThreadContext ctx, IRubyObject recv, IRubyObject data) {
        try {
            byte[] bytes = data.convertToString().getBytes();
            byte[] encoded = Hex.encode(bytes);
            return ctx.getRuntime().newString(new ByteList(encoded, false));
        } catch (RuntimeException ex) {
            throw Errors.newHexError(ctx.getRuntime(), ex.getMessage());
        }
    }
    
    @JRubyMethod(meta = true)
    public static IRubyObject decode(ThreadContext ctx, IRubyObject recv, IRubyObject data) {
        try {
            byte[] bytes = data.convertToString().getBytes();
            byte[] decoded = Hex.decode(bytes);
            return ctx.getRuntime().newString(new ByteList(decoded, false));
        } catch (RuntimeException ex) {
            throw Errors.newHexError(ctx.getRuntime(), ex.getMessage());
        }
    }
    
    public static void createHex(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyModule mHex = runtime.defineModuleUnder("Hex", krypt);
        mHex.defineClassUnder("HexError", kryptError, kryptError.getAllocator());
        mHex.defineAnnotatedMethods(RubyHex.class);
    }
        
}