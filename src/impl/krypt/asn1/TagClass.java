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
public enum TagClass {
    
    UNIVERSAL       (Masks.UNIVERSAL_MASK),
    APPLICATION     (Masks.APPLICATION_MASK),
    CONTEXT_SPECIFIC(Masks.CONTEXT_SPECIFIC_MASK),
    PRIVATE         (Masks.PRIVATE_MASK);
    
    TagClass(byte mask) {
        this.mask = mask;
    }
    
    public static TagClass forName(String name) {
        if ("IMPLICIT".equals(name))
            return CONTEXT_SPECIFIC;
        if ("EXPLICIT".equals(name))
            return CONTEXT_SPECIFIC;
        return TagClass.valueOf(name);
    }
    
    private final byte mask;
    
    public byte getMask() {
        return mask;
    }
    
    public static TagClass of(byte b) {
        switch (b) {
            case Masks.UNIVERSAL_MASK:
                return UNIVERSAL;
            case Masks.APPLICATION_MASK:
                return APPLICATION;
            case Masks.CONTEXT_SPECIFIC_MASK:
                return CONTEXT_SPECIFIC;
            case Masks.PRIVATE_MASK:
                return PRIVATE;
            default:
                throw new IllegalArgumentException("Unknown tag class: " + b);
        }
    }
    
    private static class Masks {
        static final byte UNIVERSAL_MASK        = (byte)0x00;
        static final byte APPLICATION_MASK      = (byte)0x40;
        static final byte CONTEXT_SPECIFIC_MASK = (byte)0x80;
        static final byte PRIVATE_MASK          = (byte)0xc0;
    }

}
