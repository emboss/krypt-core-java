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
package org.jruby.ext.krypt.asn1;

import impl.krypt.asn1.Tags;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Asn1 {
    
    public static void createAsn1(Ruby runtime, RubyModule krypt, RubyClass kryptError) {
        RubyModule mAsn1 = runtime.defineModuleUnder("Asn1", krypt);

        RubyClass asn1Error = mAsn1.defineClassUnder("Asn1Error", kryptError, kryptError.getAllocator());
        mAsn1.defineClassUnder("ParseError", asn1Error, asn1Error.getAllocator());
        mAsn1.defineClassUnder("SerializeError", asn1Error, asn1Error.getAllocator());

        mAsn1.defineConstant("END_OF_CONTENTS",  runtime.newFixnum(Tags.END_OF_CONTENTS));
        mAsn1.defineConstant("BOOLEAN",          runtime.newFixnum(Tags.BOOLEAN));
        mAsn1.defineConstant("INTEGER",          runtime.newFixnum(Tags.INTEGER));
        mAsn1.defineConstant("BIT_STRING",       runtime.newFixnum(Tags.BIT_STRING));
        mAsn1.defineConstant("OCTET_STRING",     runtime.newFixnum(Tags.OCTET_STRING));
        mAsn1.defineConstant("NULL",             runtime.newFixnum(Tags.NULL));
        mAsn1.defineConstant("OBJECT_ID",        runtime.newFixnum(Tags.OBJECT_ID));
        mAsn1.defineConstant("ENUMERATED",       runtime.newFixnum(Tags.ENUMERATED));
        mAsn1.defineConstant("UTF8_STRING",      runtime.newFixnum(Tags.UTF8_STRING));
        mAsn1.defineConstant("SEQUENCE",         runtime.newFixnum(Tags.SEQUENCE));
        mAsn1.defineConstant("SET",              runtime.newFixnum(Tags.SET));
        mAsn1.defineConstant("NUMERIC_STRING",   runtime.newFixnum(Tags.NUMERIC_STRING));
        mAsn1.defineConstant("PRINTABLE_STRING", runtime.newFixnum(Tags.PRINTABLE_STRING));
        mAsn1.defineConstant("T61_STRING",       runtime.newFixnum(Tags.T61_STRING));
        mAsn1.defineConstant("VIDEOTEX_STRING",  runtime.newFixnum(Tags.VIDEOTEX_STRING));
        mAsn1.defineConstant("IA5_STRING",       runtime.newFixnum(Tags.IA5_STRING));
        mAsn1.defineConstant("UTC_TIME",         runtime.newFixnum(Tags.UTC_TIME));
        mAsn1.defineConstant("GENERALIZED_TIME", runtime.newFixnum(Tags.GENERALIZED_TIME));
        mAsn1.defineConstant("GRAPHIC_STRING",   runtime.newFixnum(Tags.GRAPHIC_STRING));
        mAsn1.defineConstant("ISO64_STRING",     runtime.newFixnum(Tags.ISO64_STRING));
        mAsn1.defineConstant("GENERAL_STRING",   runtime.newFixnum(Tags.GENERAL_STRING));
        mAsn1.defineConstant("UNIVERSAL_STRING", runtime.newFixnum(Tags.UNIVERSAL_STRING));
        mAsn1.defineConstant("BMP_STRING",       runtime.newFixnum(Tags.BMP_STRING));

        Parser.createParser(runtime, mAsn1);
        Header.createHeader(runtime, mAsn1);
    }    
}
