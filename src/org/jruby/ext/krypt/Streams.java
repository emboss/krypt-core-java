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
