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
* Copyright (C) 2011-2013
* Hiroshi Nakamura <nahi@ruby-lang.org>
* Martin Bosslet <Martin.Bosslet@gmail.com>
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


/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class Asn1Tags {
    
    private Asn1Tags() {}
    
    public static final int END_OF_CONTENTS   = 0x00;
    public static final int BOOLEAN           = 0x01;
    public static final int INTEGER           = 0x02;
    public static final int BIT_STRING        = 0x03;
    public static final int OCTET_STRING      = 0x04;
    public static final int NULL              = 0x05;
    public static final int OBJECT_ID         = 0x06;
    
    public static final int ENUMERATED        = 0x0a;
    
    public static final int UTF8_STRING       = 0x0c;
    
    public static final int SEQUENCE          = 0x10;
    public static final int SET               = 0x11;
    public static final int NUMERIC_STRING    = 0x12;
    public static final int PRINTABLE_STRING  = 0x13;
    public static final int T61_STRING        = 0x14;
    public static final int VIDEOTEX_STRING   = 0x15;
    public static final int IA5_STRING        = 0x16;
    public static final int UTC_TIME          = 0x17;
    public static final int GENERALIZED_TIME  = 0x18;
    public static final int GRAPHIC_STRING    = 0x19;
    public static final int ISO64_STRING      = 0x1a;
    public static final int GENERAL_STRING    = 0x1b;
    public static final int UNIVERSAL_STRING  = 0x1c;
    
    public static final int BMP_STRING        = 0x1e;
}
