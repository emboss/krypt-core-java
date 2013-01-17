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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.jruby.Ruby;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.IOInputStream;
import org.jruby.util.IOOutputStream;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class Streams {
   private Streams() { }
   
   public static InputStream tryWrapAsInputStream(Ruby runtime, IRubyObject io) {
        try {
            return new IOInputStream(io);
        }
        catch (IllegalArgumentException ex) {
            throw runtime.newArgumentError(ex.getMessage());
        }
    }
    
   public static OutputStream tryWrapAsOuputStream(Ruby runtime, IRubyObject io) {
        try {
            return new IOOutputStream(io);
        }
        catch (IllegalArgumentException ex) {
            throw runtime.newArgumentError(ex.getMessage());
        }
    }
   
    public static InputStream asInputStreamDer(Ruby runtime, IRubyObject value) {
        if (value.respondsTo("read"))
            return Streams.tryWrapAsInputStream(runtime, value);
        else
            return new ByteArrayInputStream(toDerIfPossible(value).convertToString().getBytes());
    }
    
    public static InputStream asInputStreamPem(Ruby runtime, IRubyObject value) {
        if (value.respondsTo("read"))
            return Streams.tryWrapAsInputStream(runtime, value);
        else
            return new ByteArrayInputStream(toPemIfPossible(value).convertToString().getBytes());
    }
    
    private static IRubyObject convertData(IRubyObject obj, String convertMeth) {
        return obj.callMethod(obj.getRuntime().getCurrentContext(), convertMeth);
    }

    private static IRubyObject convertDataIfPossible(IRubyObject data, String convertMeth) {
        if(data.respondsTo(convertMeth)) {
            return convertData(data, convertMeth);
        } else {
            return data;
        }
    }
    
    public static IRubyObject toDer(IRubyObject obj) {
        return convertData(obj, "to_der");
    }

    public static IRubyObject toDerIfPossible(IRubyObject der) {
        return convertDataIfPossible(der, "to_der");
    }
    
    public static IRubyObject toPem(IRubyObject obj) {
        return convertData(obj, "to_pem");
    }

    public static IRubyObject toPemIfPossible(IRubyObject pem) {
        return convertDataIfPossible(pem, "to_pem");
    }
   
    public static void tryClose(Ruby runtime, InputStream in) {
        try {
            in.close();
        }
        catch (IOException ex) {
            throw runtime.newRuntimeError(ex.getMessage());
        }
    }
    
    public static void tryClose(Ruby runtime, OutputStream out) {
        try {
            out.close();
        }
        catch (IOException ex) {
            throw runtime.newRuntimeError(ex.getMessage());
        }
    }
    
    public static byte[] consume(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int read;
        byte[] buffer = new byte[8192];
        while ((read = in.read(buffer)) != -1) {
            baos.write(buffer, 0, read);
        }
        if (baos.size() == 0)
            return null;
        return baos.toByteArray();
    }
    
    public static boolean isConsumed(InputStream in) {
        try {
            if (in.read() != -1)
                return false;
            return true;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
