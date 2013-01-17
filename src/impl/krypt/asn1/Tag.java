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
package impl.krypt.asn1;

/**
 * 
 * @author <a href="mailto:Martin.Bosslet@gmail.com">Martin Bosslet</a>
 */
public class Tag {

    private int tag;
    private TagClass tc;
    private boolean isConstructed;
    private byte[] encoding;

    public Tag(int tag, TagClass tc, boolean isConstructed) {
        this(tag, tc, isConstructed, null);
    }

    public Tag(int tag, TagClass tc, boolean isConstructed, byte[] encoding) {
        this.tag = tag;
        this.tc = tc;
        this.isConstructed = isConstructed;
        this.encoding = encoding;
    }

    public byte[] getEncoding() {
        if (encoding == null) {
            encoding = computeEncoding();
        }
        return encoding;
    }

    public boolean isConstructed() {
        return isConstructed;
    }
    
    public void setConstructed(boolean isConstructed) {
        if (isConstructed == this.isConstructed)
            return;
        this.isConstructed = isConstructed;
        this.encoding = null;
    }

    public int getTag() {
        return tag;
    }
    
    public void setTag(int tag) {
        if (tag == this.tag)
            return;
        this.tag = tag;
        this.encoding = null;
    }
    
    public void invalidateEncoding() {
        this.encoding = null;
    }

    public TagClass getTagClass() {
        return tc;
    }
    
    public void setTagClass(TagClass tagClass) {
        if (tagClass == this.tc)
            return;
        this.tc = tagClass;
        this.encoding = null;
    }
    
    public boolean hasBeenComputed() {
        return encoding != null;
    }

    private byte[] computeEncoding() {
        if (tag < 31) {
            byte tagByte = isConstructed ? Header.CONSTRUCTED_MASK : (byte) 0x00;
            tagByte |= tc.getMask();
            tagByte |= (byte) (tag & 0xff);
            return new byte[]{tagByte};
        } else {
            return computeComplexTag();
        }
    }

    private byte[] computeComplexTag() {
        byte tagByte = isConstructed ? Header.CONSTRUCTED_MASK : (byte) 0x00;
        tagByte |= tc.getMask();
        tagByte |= Header.COMPLEX_TAG_MASK;

        int numShifts = determineNumberOfShifts(tag, 7);
        byte[] out = new byte[numShifts + 1];
        int tmpTag = tag;

        out[0] = tagByte;
        for (int i = numShifts; i > 0; i--) {
            tagByte = (byte) (tmpTag & 0x7f);
            if (i != numShifts) {
                tagByte |= Header.INFINITE_LENGTH_MASK;
            }
            out[i] = tagByte;
            tmpTag >>= 7;
        }
        return out;
    }

    static int determineNumberOfShifts(int value, int shiftBy) {
        int i;
        for (i = 0; value > 0; i++) {
            value >>= shiftBy;
        }
        return i;
    }
}
        
