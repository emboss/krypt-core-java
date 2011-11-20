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

import impl.krypt.asn1.ParseException;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.TagClass;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import org.jruby.Ruby;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyIO;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyMethod;
import org.jruby.ext.krypt.Errors;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.jruby.util.IOOutputStream;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@googlemail.com">Martin Bosslet</a>
 */
public class Header extends RubyObject {
    
    public static void createHeader(Ruby runtime, RubyModule mAsn1) {
        mAsn1.defineClassUnder("Header", runtime.getObject(), ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR)
             .defineAnnotatedMethods(Header.class);
    }
    
    private final ParsedHeader h;
    
    private final IRubyObject tag;
    private final IRubyObject tagClass;
    private final IRubyObject isConstructed;
    private final IRubyObject isInfLen;
    private final IRubyObject len;
    private final IRubyObject hlen;
    
    public Header(Ruby runtime, RubyClass type, impl.krypt.asn1.ParsedHeader h) {
        super(runtime, type);
        if (h == null) throw new NullPointerException();
    
        this.h = h;
        
        this.tag = RubyFixnum.newFixnum(runtime, h.getTag());
        this.tagClass = tagClassFor(runtime, h.getTagClass());
        this.isConstructed = RubyBoolean.newBoolean(runtime, h.isConstructed());
        this.isInfLen = RubyBoolean.newBoolean(runtime, h.isInfiniteLength());
        this.len = RubyFixnum.newFixnum(runtime, h.getLength());
        this.hlen = RubyFixnum.newFixnum(runtime, h.getHeaderLength());
    }
    
    private static IRubyObject tagClassFor(Ruby runtime, TagClass tc) {
        switch(tc) {
            case UNIVERSAL:
                return RubySymbol.newSymbol(runtime, TagClass.UNIVERSAL.name());
            case CONTEXT_SPECIFIC:
                return RubySymbol.newSymbol(runtime, TagClass.CONTEXT_SPECIFIC.name());
            case APPLICATION:
                return RubySymbol.newSymbol(runtime, TagClass.APPLICATION.name());
            case PRIVATE:
                return RubySymbol.newSymbol(runtime, TagClass.PRIVATE.name());
            default:
                throw runtime.newRuntimeError("Unkown TagClass " + tc);
        }
    }
    
    @JRubyMethod
    public IRubyObject tag() {
        return tag;
    }
    
    @JRubyMethod
    public IRubyObject tag_class() {
        return tagClass;
    }
    
    @JRubyMethod(name="constructed?")
    public IRubyObject is_constructed() {
        return isConstructed;
    }
    
    @JRubyMethod(name="infinite_len?")
    public IRubyObject is_infinite_len() {
        return isInfLen;
    }
    
    @JRubyMethod(name={"size","length"})
    public IRubyObject size() {
        return len;
    }
    
    @JRubyMethod(name={"header_size","header_length"})
    public IRubyObject header_size() {
        return hlen;
    }
    
    @JRubyMethod
    public IRubyObject encode_to(IRubyObject io) {
        h.encodeTo(new IOOutputStream(io));
        return this;
    }
    
    @JRubyMethod
    public IRubyObject bytes() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        h.encodeTo(baos);
        return getRuntime().newString(new ByteList(baos.toByteArray(), false));
    }
    
    @JRubyMethod
    public IRubyObject skip_value() {
        h.skipValue();
        return this;
    }
    
    @JRubyMethod
    public IRubyObject value() {
        byte[] value = h.getValue();
        if (value == null || value.length == 0)
            return getRuntime().getNil();
        else
            return getRuntime().newString(new ByteList(value, false));
    }
    
    @JRubyMethod(optional=1)
    public IRubyObject value_io(IRubyObject[] args) {
        Ruby runtime = getRuntime();
        IRubyObject valuesOnly = args.length > 0 ? args[0] : RubyBoolean.newBoolean(runtime, true);
        try {
            InputStream valueStream = h.getValueStream(valuesOnly.isTrue());
            return new RubyIO(runtime, valueStream);
        } 
        catch (ParseException ex) {
            throw Errors.newParseError(runtime, ex.getMessage());
        }
    }
    
    @Override
    @JRubyMethod
    public IRubyObject to_s() {
        String s = new StringBuilder()
                .append("Tag: ").append(h.getTag())
                .append(" Tag Class: ").append(h.getTagClass().name())
                .append(" Length: ").append(h.getLength())
                .append(" Constructed: ").append(h.isConstructed())
                .append(" Infinite Length: ").append(h.isInfiniteLength())
                .toString();
        return getRuntime().newString(s);
    }
}
