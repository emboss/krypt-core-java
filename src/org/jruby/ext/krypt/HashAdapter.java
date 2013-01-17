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
