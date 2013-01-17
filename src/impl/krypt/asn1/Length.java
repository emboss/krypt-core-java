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
public class Length {

    private boolean isInfiniteLength;
    private int length;
    private byte[] encoding;

    public Length(boolean isInfiniteLength) {
        this(0, isInfiniteLength, null);
    }

    public Length(int length, boolean isInfiniteLength, byte[] encoding) {
        this.isInfiniteLength = isInfiniteLength;
        this.length = length;
        this.encoding = encoding;
    }

    public byte[] getEncoding() {
        if (encoding == null) {
            encoding = computeEncoding();
        }
        return encoding;
    }

    public boolean isInfiniteLength() {
        return isInfiniteLength;
    }
    
    public void setInfiniteLength(boolean isInfiniteLength) {
        if (isInfiniteLength == this.isInfiniteLength)
            return;
        this.isInfiniteLength = isInfiniteLength;
        this.encoding = null;
    }

    public int getLength() {
        return length;
    }
    
    public void setLength(int length) {
        if (length == this.length)
            return;
        this.length = length;
        this.encoding = null;
    }
    
    public void invalidateEncoding() {
        this.encoding = null;
        this.length = 0;
    }
    
    public boolean hasBeenComputed() {
        return encoding != null;
    }
    
    private byte[] computeEncoding() {
        if (isInfiniteLength) {
            return new byte[]{Header.INFINITE_LENGTH_MASK};
        } else if (length <= 127) {
            return new byte[]{(byte) (length & 0xff)};
        } else {
            return computeComplexLength();
        }
    }

    private byte[] computeComplexLength() {
        int numShifts = Tag.determineNumberOfShifts(length, 8);
        int tmp = length;
        byte[] out = new byte[numShifts + 1];
        out[0] = (byte) (numShifts & 0xff);
        out[0] |= Header.INFINITE_LENGTH_MASK;

        for (int i = numShifts; i > 0; i--) {
            out[i] = (byte) (tmp & 0xff);
            tmp >>= 8;
        }

        return out;
    }
}
