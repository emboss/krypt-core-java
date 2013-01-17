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

import impl.krypt.asn1.ParseException;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.ParserFactory;
import java.io.InputStream;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.ext.krypt.Streams;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class RubyParser extends RubyObject {
    
    private static ObjectAllocator PARSER_ALLOCATOR = new ObjectAllocator() {
        @Override
        public IRubyObject allocate(Ruby runtime, RubyClass type) {
            return new RubyParser(runtime, type);
        }
    };
    
    private static RubyClass cHeader;
    
    public static void createParser(Ruby runtime, RubyModule mASN1) {
        mASN1.defineClassUnder("Parser", runtime.getObject(), PARSER_ALLOCATOR)
             .defineAnnotatedMethods(RubyParser.class);
        cHeader = ((RubyModule)runtime.getModule("Krypt")
                                           .getConstant("ASN1"))
                                           .getClass("Header");
    }
    
    private final impl.krypt.asn1.Parser parser;
    
    public RubyParser(Ruby runtime, RubyClass type) {
        super(runtime, type);
        
        this.parser = new ParserFactory().newHeaderParser();
    }
    
    @Override
    @JRubyMethod()
    public IRubyObject initialize(ThreadContext ctx) {
        return this;
    }
    
    @JRubyMethod()
    public IRubyObject next(ThreadContext ctx, IRubyObject io) {
        Ruby runtime = ctx.getRuntime();
        InputStream in = asStream(runtime, io);
        return parseHeader(runtime, cHeader, in);
    }
    
    private IRubyObject parseHeader(Ruby runtime, RubyClass headerClass, InputStream in) {
        try {
            ParsedHeader h = parser.next(in);
            if (h == null) {
                return runtime.getNil();
            }
            else {
                return new RubyHeader(runtime, headerClass, h);
            }
        } 
        catch (ParseException ex) {
            throw Errors.newParseError(runtime, ex.getMessage());
        }
    }
    
    private static InputStream asStream(Ruby runtime, IRubyObject obj) {
        if (!obj.respondsTo("read"))
            throw Errors.newError(runtime, "ArgumentError", "Object must respond to read");
        return Streams.tryWrapAsInputStream(runtime, obj);
    }
}
