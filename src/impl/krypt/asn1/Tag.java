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
        
