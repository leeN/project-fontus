package com.sap.fontus.config.abort;

import com.sap.fontus.taintaware.shared.IASTaintRanges;

import java.util.List;

import static com.sap.fontus.utils.Utils.convertStackTrace;

public class AbortObject {
    private final String sinkFunction;
    private final String sinkName;
    private final String payload;
    private final IASTaintRanges ranges;
    private final List<String> stackTrace;

    public AbortObject(String sinkFunction, String sinkName, String payload, IASTaintRanges ranges, List<String> stackTrace) {
        this.sinkFunction = sinkFunction;
        this.sinkName = sinkName;
        this.payload = payload;
        this.ranges = ranges;
        this.stackTrace = stackTrace;
    }

    public String getSinkFunction() {
        return sinkFunction;
    }

    public String getSinkName() {
        return sinkName;
    }

    public String getPayload() {
        return payload;
    }

    public IASTaintRanges getRanges() {
        return ranges;
    }

    public List<String> getStackTrace() {
        return stackTrace;
    }
}
