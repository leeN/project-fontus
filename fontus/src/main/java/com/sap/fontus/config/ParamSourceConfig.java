package com.sap.fontus.config;

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.sap.fontus.asm.FunctionCall;

import javax.xml.bind.annotation.XmlElement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ParamSourceConfig {

    public ParamSourceConfig() {
        this.sources = new ArrayList<>();
    }

    public ParamSourceConfig(List<Source> sources) {
        this.sources = sources;
    }

    public void append(ParamSourceConfig sourceConfig) {
        this.sources.addAll(sourceConfig.sources);
    }

    public Source getSourceForFunction(FunctionCall fc) {
        for (Source s : this.sources) {
            if (s.getFunction().equals(fc)) {
                return s;
            }
        }
        return null;
    }

    public Source getSourceWithName(String name) {
        for (Source s : this.sources) {
            if (s.getName().equals(name)) {
                return s;
            }
        }
        return null;
    }

    public boolean containsFunction(FunctionCall fc) {
        return (this.getSourceForFunction(fc) != null);
    }

    public List<Source> getSources() {
        return Collections.unmodifiableList(this.sources);
    }

    @JacksonXmlElementWrapper(localName = "psources")
    @XmlElement(name = "source")
    private final List<Source> sources;

    @Override
    public String toString() {
        return "ParamSourceConfig{" +
                "sources=" + this.sources +
                '}';
    }
}
