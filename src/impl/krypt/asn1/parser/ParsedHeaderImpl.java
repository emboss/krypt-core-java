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
package impl.krypt.asn1.parser;

import impl.krypt.asn1.Asn1Object;
import impl.krypt.asn1.EncodableHeader;
import impl.krypt.asn1.Header;
import impl.krypt.asn1.Length;
import impl.krypt.asn1.ParseException;
import impl.krypt.asn1.ParsedHeader;
import impl.krypt.asn1.SerializeException;
import impl.krypt.asn1.Tag;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
class ParsedHeaderImpl implements ParsedHeader {

    private final Tag tag;
    private final Length length;
    private final InputStream in;
    private final PullHeaderParser parser;
    
    private byte[] cachedValue;
    private InputStream cachedValueStream;
    private boolean consumed = false;

    ParsedHeaderImpl(Tag tag, 
                     Length length, 
                     InputStream in,
                     PullHeaderParser parser) {
        if (tag == null) throw new NullPointerException();
        if (length == null) throw new NullPointerException();
        if (in == null) throw new NullPointerException();
        if (parser == null) throw new NullPointerException();
        
	this.tag = tag;
	this.length = length;
	this.in = in;
        this.parser = parser;
   }

    @Override
    public void skipValue() {
	getValue();
    }

    @Override
    public byte[] getValue() {
	if (cachedValue == null) {
            if (consumed)
                throw new ParseException("The stream has already been consumed");
            
            InputStream stream = getValueStream(false);
            byte[] ret = doGetValue(stream);
            cachedValue = ret.length == 0 ? null : ret;
            cachedValueStream = null;
            consumed = true;
        }
        return cachedValue;
    }
    
    private byte[] doGetValue(InputStream stream) {
        try {
            return consume(stream);
        }
        finally {
            try {
                stream.close();
            }
            catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    @Override
    public InputStream getValueStream(boolean valuesOnly) {
        if (consumed && cachedValueStream == null)
            throw new ParseException("The stream is already consumed");
        
        if (cachedValueStream == null) {
            cachedValueStream = cacheStream(valuesOnly);
            consumed = true;
        }
        
        return cachedValueStream;
    }
    
    private InputStream cacheStream(boolean valuesOnly) {
        if (length.isInfiniteLength())
            return new ChunkInputStream(in, parser, valuesOnly);
        else
            return new DefiniteInputStream(in, length.getLength());
    }

    private byte[] consume(InputStream stream) {
        
        byte[] buf = new byte[8192];
        int read;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        try {
            while ((read = stream.read(buf)) != -1) {
                baos.write(buf, 0, read);
            }
        }
        catch (IOException ex) {
                throw new ParseException(ex);
        }
        
        return baos.toByteArray();
    }

    @Override
    public Length getLength() {
        return length;
    }

    @Override
    public Tag getTag() {
        return tag;
    }
    
    @Override
    public int getHeaderLength() {
	return tag.getEncoding().length + length.getEncoding().length;
    }

    @Override
    public Asn1Object getObject() {
        Header h = new EncodableHeader(tag, length);
        return new Asn1Object(h, getValue());
    }
    
    @Override
    public void encodeTo(OutputStream out) {
	try {
            out.write(tag.getEncoding());
            out.write(length.getEncoding());
        }
        catch (IOException ex) {
            throw new SerializeException(ex);
        }
    }
}
