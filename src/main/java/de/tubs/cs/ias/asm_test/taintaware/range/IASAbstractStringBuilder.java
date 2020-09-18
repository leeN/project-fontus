package de.tubs.cs.ias.asm_test.taintaware.range;

import de.tubs.cs.ias.asm_test.Constants;
import de.tubs.cs.ias.asm_test.taintaware.shared.*;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

@SuppressWarnings({"unused", "Since15"})
public abstract class IASAbstractStringBuilder implements IASTaintRangeAware, IASAbstractStringBuilderable {
    protected final StringBuilder stringBuilder;
    private IASTaintInformation taintInformation;

    public IASAbstractStringBuilder() {
        this.stringBuilder = new StringBuilder();
    }

    public IASAbstractStringBuilder(int capacity) {
        this.stringBuilder = new StringBuilder(capacity);
    }

    public IASAbstractStringBuilder(IASStringable str) {
        this.stringBuilder = new StringBuilder(str.getString());
        if (str.isTainted()) {
            this.taintInformation = new IASTaintInformation(((IASString) str).getTaintRanges());
        }
    }

    public IASAbstractStringBuilder(CharSequence seq) {
        IASString str = IASString.valueOf(seq);
        this.stringBuilder = new StringBuilder(str.length() + 16);
        this.append(str);
    }

    private void appendShifted(List<IASTaintRange> ranges, boolean merge) {
        if (ranges.size() == 0) {
            return;
        }

        if (isUninitialized()) {
            this.taintInformation = new IASTaintInformation();
        }

        IASTaintRangeUtils.shiftRight(ranges, this.length());
        this.taintInformation.appendRanges(ranges, merge);
    }

    @Override
    public void initialize() {
        if (isUninitialized()) {
            this.taintInformation = new IASTaintInformation();
        }
    }

    @Override
    public void setTaint(boolean taint) {
        this.setTaint(taint ? IASTaintSourceRegistry.TS_CS_UNKNOWN_ORIGIN : null);
    }

    @Override
    public void setTaint(IASTaintSource source) {
        if (source != null) {
            if (!this.isTainted()) {
                if (isUninitialized()) {
                    this.taintInformation = new IASTaintInformation();
                }
                this.taintInformation.addRange(0, this.length(), source);
            }
        } else {
            this.taintInformation = null;
        }
    }

    @Override
    public void setTaint(List<IASTaintRange> ranges) {
        if (ranges == null || ranges.size() == 0) {
            this.taintInformation = null;
        } else {
            this.taintInformation = new IASTaintInformation(ranges);
        }
    }

    @Override
    public boolean isTainted() {
        if (isUninitialized()) {
            return false;
        }
        return this.taintInformation.isTainted();
    }

    public IASAbstractStringBuilder append(Object obj) {
        IASString iasString = IASString.valueOf(obj);
        this.append(iasString);
        return this;
    }

    public IASAbstractStringBuilder append(IASStringable str) {
        return this.append(str, true);
    }


    public IASAbstractStringBuilder append(IASStringable str, boolean merge) {
        IASString string = IASString.valueOf(str);
        List<IASTaintRange> ranges = string.getTaintRanges();
        this.appendShifted(ranges, merge);

        this.stringBuilder.append(string.getString());
        return this;
    }

    public IASAbstractStringBuilder append(IASAbstractStringBuilderable strb) {
        IASString string = (IASString) strb.toIASString();
        List<IASTaintRange> ranges = string.getTaintRanges();
        this.appendShifted(ranges);

        this.stringBuilder.append(string.getString());

        return this;
    }

    protected void appendShifted(List<IASTaintRange> ranges) {
        this.appendShifted(ranges, false);
    }

    protected List<IASTaintRange> getAllRanges() {
        return isTainted() ? this.taintInformation.getTaintRanges() : new ArrayList<>(0);
    }

    @Override
    public List<IASTaintRange> getTaintRanges() {
        List<IASTaintRange> ranges = getAllRanges();
        IASTaintRangeUtils.adjustRanges(ranges, 0, this.length(), 0);
        return ranges;
    }

    public IASAbstractStringBuilder append(CharSequence cs) {
        IASString iasString = IASString.valueOf(cs);
        return this.append(iasString);
    }

    public IASAbstractStringBuilder append(CharSequence s, int start, int end) {
        IASString iasString = IASString.valueOf(s);
        return this.append(iasString.substring(start, end));
    }

    public IASAbstractStringBuilder append(char[] s, int offset, int len) {
        this.stringBuilder.append(s, offset, len);
        return this;
    }

    public IASAbstractStringBuilder append(char[] str) {
        this.stringBuilder.append(str);
        return this;
    }

    public IASAbstractStringBuilder append(boolean b) {
        this.stringBuilder.append(b);
        return this;
    }

    public IASAbstractStringBuilder append(char c) {
        this.stringBuilder.append(c);
        return this;
    }

    public IASAbstractStringBuilder append(int i) {
        this.stringBuilder.append(i);
        return this;
    }

    public IASAbstractStringBuilder append(long lng) {
        this.stringBuilder.append(lng);
        return this;
    }

    public IASAbstractStringBuilder append(float f) {
        this.stringBuilder.append(f);
        return this;
    }

    public IASAbstractStringBuilder append(double d) {
        this.stringBuilder.append(d);
        return this;
    }

    public IASAbstractStringBuilder appendCodePoint(int codePoint) {
        this.stringBuilder.appendCodePoint(codePoint);
        return this;
    }

    public IASAbstractStringBuilder delete(int start, int end) {
        this.stringBuilder.delete(start, end);
        if (isTainted()) {
            this.taintInformation.removeTaintFor(start, end, true);
        }
        return this;
    }

    public IASAbstractStringBuilder deleteCharAt(int index) {
        this.stringBuilder.deleteCharAt(index);
        if (isTainted()) {
            this.taintInformation.removeTaintFor(index, index + 1, true);
        }
        return this;
    }

    public IASAbstractStringBuilder replace(int start, int end, IASStringable str) {
        this.stringBuilder.replace(start, end, str.toString());
        if (isUninitialized() && str.isTainted()) {
            this.taintInformation = new IASTaintInformation();
        }
        if (this.isTainted() || str.isTainted()) {
            this.taintInformation.replaceTaintInformation(start, end, ((IASString) str).getTaintRanges(), str.length(), true);
        }
        return this;
    }

    public IASAbstractStringBuilder insert(int index, char[] str, int offset,
                                           int len) {
        IASString iasString = IASString.valueOf(str, offset, len);
        this.insert(index, iasString);
        return this;
    }

    public IASAbstractStringBuilder insert(int offset, Object obj) {
        IASString iasString = IASString.valueOf(obj);
        this.insert(offset, iasString);
        return this;
    }

    public IASAbstractStringBuilder insert(int offset, IASStringable str) {
        if (isUninitialized() && str.isTainted()) {
            this.taintInformation = new IASTaintInformation();
        }
        if (this.isTainted() || str.isTainted()) {
            this.taintInformation.insert(offset, ((IASString) str).getTaintRanges(), str.length());
        }
        this.stringBuilder.insert(offset, str.toString());
        return this;
    }

    public IASAbstractStringBuilder insert(int offset, char[] str) {
        this.insert(offset, str, 0, str.length);
        return this;
    }

    public IASAbstractStringBuilder insert(int dstOffset, CharSequence s) {
        this.insert(dstOffset, s, 0, s.length());
        return this;
    }

    public IASAbstractStringBuilder insert(int dstOffset, CharSequence s,
                                           int start, int end) {
        IASString iasString = IASString.valueOf(s);
        iasString = iasString.substring(start, end);
        this.insert(dstOffset, iasString);
        return this;
    }

    public IASAbstractStringBuilder insert(int offset, boolean b) {
        IASString s = IASString.valueOf(b);
        return this.insert(offset, s);
    }

    public IASAbstractStringBuilder insert(int offset, char c) {
        IASString s = IASString.valueOf(c);
        return this.insert(offset, s);
    }

    public IASAbstractStringBuilder insert(int offset, int i) {
        IASString s = IASString.valueOf(i);
        return this.insert(offset, s);
    }

    public IASAbstractStringBuilder insert(int offset, long l) {
        IASString s = IASString.valueOf(l);
        return this.insert(offset, s);
    }

    public IASAbstractStringBuilder insert(int offset, float f) {
        IASString s = IASString.valueOf(f);
        return this.insert(offset, s);
    }

    public IASAbstractStringBuilder insert(int offset, double d) {
        IASString s = IASString.valueOf(d);
        return this.insert(offset, s);
    }

    public int indexOf(IASStringable str) {
        return this.stringBuilder.indexOf(str.getString());
    }

    public int indexOf(IASStringable str, int fromIndex) {
        return this.stringBuilder.indexOf(str.toString(), fromIndex);
    }

    public int lastIndexOf(IASStringable str) {
        return this.stringBuilder.lastIndexOf(str.toString());
    }

    public int lastIndexOf(IASStringable str, int fromIndex) {
        return this.stringBuilder.lastIndexOf(str.toString(), fromIndex);
    }

    public IASAbstractStringBuilder reverse() {
        this.stringBuilder.reverse();
        if (isTainted()) {
            this.taintInformation.reversed(this.length());
        }
        handleSurrogatesForReversed();

        return this;
    }

    private void handleSurrogatesForReversed() {
        if (!isTainted()) {
            return;
        }

        char[] chars = this.toString().toCharArray();
        for (int i = 0; i < this.length() - 1; i++) {
            char highSur = chars[i];
            char lowSur = chars[i + 1];
            if (Character.isLowSurrogate(lowSur) && Character.isHighSurrogate(highSur)) {
                IASTaintRange oldHighRange = this.taintInformation.cutTaint(i);
                IASTaintRange oldLowRange = this.taintInformation.cutTaint(i + 1);

                List<IASTaintRange> ranges = new ArrayList<IASTaintRange>(2);

                if (oldLowRange != null) {
                    IASTaintRange newHighRange = oldLowRange.shiftRight(-1);
                    ranges.add(newHighRange);
                }
                if (oldHighRange != null) {
                    IASTaintRange newLowRange = oldHighRange.shiftRight(1);
                    ranges.add(newLowRange);
                }

                this.taintInformation.replaceTaintInformation(i, i + 2, ranges, 2, false);
            }
        }
    }

    @Override
    public String toString() {
        return this.stringBuilder.toString();
    }

    public IASString toIASString() {
        return new IASString(this.stringBuilder.toString(), this.getTaintRanges());
    }

    public int capacity() {
        return this.stringBuilder.capacity();
    }

    public IASString substring(int start) {
        return this.toIASString().substring(start);
    }

    public IASString substring(int start, int end) {
        return this.toIASString().substring(start, end);
    }

    public void setCharAt(int index, char c) {
        this.stringBuilder.setCharAt(index, c);
        if (isTainted()) {
            this.taintInformation.removeTaintFor(index, index + 1, false);
        }
    }

    public void ensureCapacity(int minimumCapacity) {
        this.stringBuilder.ensureCapacity(minimumCapacity);
    }

    public void trimToSize() {
        this.stringBuilder.trimToSize();
    }

    @Override
    public int length() {
        return this.stringBuilder.length();
    }

    @Override
    public char charAt(int index) {
        return this.stringBuilder.charAt(index);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        return this.toIASString().subSequence(start, end);
    }

    @Override
    public IntStream chars() {
        return this.stringBuilder.chars();
    }

    @Override
    public IntStream codePoints() {
        return this.stringBuilder.codePoints();
    }

    @Override
    public int codePointCount(int beginIndex, int endIndex) {
        return this.stringBuilder.codePointCount(beginIndex, endIndex);
    }

    public StringBuilder getStringBuilder() {
        return this.stringBuilder;
    }

    public void setLength(int newLength) {
        this.stringBuilder.setLength(newLength);
        if (isTainted()) {
            this.taintInformation.resize(0, newLength, 0);
        }
    }

    public IASTaintInformation getTaintInformation() {
        return this.taintInformation;
    }

    public boolean isUninitialized() {
        return this.taintInformation == null;
    }

    @Override
    public int compareTo(IASAbstractStringBuilderable o) {
        if (Constants.JAVA_VERSION < 11) {
            return this.toIASString().compareTo(IASString.valueOf(o));
        } else {
            return this.stringBuilder.compareTo(o.getStringBuilder());
        }
    }

    @Override
    public boolean isTaintedAt(int index) {
        if (isUninitialized()) {
            return false;
        }
        return this.taintInformation.isTaintedAt(index);
    }
}
