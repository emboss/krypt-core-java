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
package org.jruby.ext.krypt;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import org.jruby.RubyArray;
import org.jruby.RubyHash;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class HashAdapter implements Map {
    private final RubyHash inner;

    public HashAdapter(RubyHash inner) {
        if (inner == null) throw new NullPointerException("inner");
        this.inner = inner;
    }

    @Override public void clear() { inner.clear(); }
    @Override public boolean containsKey(Object key) { return inner.containsKey(key); }
    @Override public boolean containsValue(Object value) { return inner.containsValue(value); }
    @Override public Set entrySet() { return inner.entrySet(); }
    @Override public Object get(Object key) { return inner.get(key); }
    @Override public boolean isEmpty() { return inner.isEmpty(); }
    @Override public Set keySet() { return inner.keySet(); }
    @Override public Object put(Object key, Object value) { return inner.put(key, value); }
    @Override public void putAll(Map m) { inner.putAll(m); }
    @Override public Object remove(Object key) { return inner.remove(key); }
    @Override public int size() { return inner.size(); }
    @Override public Collection values() { return inner.values(); }
    
    public Integer getIntegerFixnum(Object key) {
        Long l = (Long) inner.get(key);
        if (l == null) return null;
        if (l > Integer.MAX_VALUE) throw new RuntimeException("Value too large: " + l);
        return l.intValue();
    }
    
    public Long getLongFixnum(Object key) {
        return (Long) inner.get(key);
    }
    
    public Boolean getBoolean(Object key) {
        return (Boolean) inner.get(key);
    }
    
    public String getString(Object key) {
        return (String) inner.get(key);
    }
    
    public String getSymbol(Object key) {
        IRubyObject iro = (IRubyObject) inner.get(key);
        if (iro == null) return null;
        return iro.asJavaString();
    }
    
    public RubyArray getArray(Object key) {
        return (RubyArray) inner.get(key);
    }
    
    public HashAdapter getHash(Object key) {
        RubyHash h = (RubyHash) inner.get(key);
        if (h == null) return null;
        return new HashAdapter(h);
    }
    
    public IRubyObject getObject(ThreadContext ctx, IRubyObject key) {
        return inner.op_aref(ctx, key);
    }
}
