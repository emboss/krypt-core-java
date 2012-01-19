/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package impl.krypt.asn1;

/**
 *
 * @author martin
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
