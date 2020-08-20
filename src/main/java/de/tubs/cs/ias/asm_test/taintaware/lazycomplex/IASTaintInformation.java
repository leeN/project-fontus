package de.tubs.cs.ias.asm_test.taintaware.lazycomplex;

import de.tubs.cs.ias.asm_test.config.Configuration;
import de.tubs.cs.ias.asm_test.taintaware.lazycomplex.operations.BaseOperation;
import de.tubs.cs.ias.asm_test.taintaware.shared.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class IASTaintInformation implements IASTaintInformationable {
    private String previousString;
    private IASTaintInformation previousInformation;
    private IASOperation operation;
    private volatile List<IASTaintRange> cache;

    public IASTaintInformation(String previousString, IASTaintInformation previousInformation, IASOperation operation) {
        this.previousString = previousString;
        this.previousInformation = previousInformation;
        this.operation = Objects.requireNonNull(operation);
    }

    public IASTaintInformation(BaseOperation operation) {
        this.previousString = null;
        this.previousInformation = null;
        this.operation = Objects.requireNonNull(operation);
    }

    public IASTaintInformation() {
        this.previousString = null;
        this.previousInformation = null;
        this.operation = new BaseOperation();
    }

    public IASTaintInformation(List<IASTaintRange> taintRanges) {
        this.previousString = null;
        this.previousInformation = null;
        this.operation = new BaseOperation(taintRanges);
    }

    public synchronized boolean isTainted() {
        List<IASTaintRange> ranges = this.evaluate();
        if (ranges.size() == 0) {
            return false;
        } else if (ranges.size() == 1) {
            IASTaintRange range = ranges.get(0);
            return !(range.getStart() == range.getEnd());
        } else {
            return true;
        }
    }

    @Override
    public synchronized IASTaintSource getTaintFor(int position) {
        return new IASTaintRanges(this.getTaintRanges()).getTaintFor(position);
    }

    @Override
    public synchronized boolean isTaintedAt(int index) {
        return new IASTaintRanges(this.getTaintRanges()).isTaintedAt(index);
    }

    private synchronized List<IASTaintRange> evaluate() {
        if (this.cache == null) {
            List<IASTaintRange> ranges = null;
            if (this.previousInformation != null) {
                ranges = new ArrayList<>(this.previousInformation.evaluate());
            }
            List<IASTaintRange> cache = this.operation.apply(this.previousString, ranges);
            IASTaintRangeUtils.merge(cache);
            cache = Collections.unmodifiableList(cache);

            if (Configuration.getConfiguration().useCaching()) {
                this.cache = cache;
                this.previousString = null;
                this.previousInformation = null;
                this.operation = null;
            }
            return cache;
        }
        return this.cache;
    }

    public synchronized List<IASTaintRange> getTaintRanges() {
        return new ArrayList<>(this.evaluate());
    }
}
