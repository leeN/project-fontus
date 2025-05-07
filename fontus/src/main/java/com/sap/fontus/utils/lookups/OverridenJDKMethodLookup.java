package com.sap.fontus.utils.lookups;

import com.sap.fontus.instrumentation.Method;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class OverridenJDKMethodLookup {

    private final ConcurrentHashMap<String, Set<Method>> overridenMethods = new ConcurrentHashMap<>();
    private OverridenJDKMethodLookup() {

    }

    public Set<Method> getOverridenMethods(String clazz) {
        return this.overridenMethods.get(clazz);
    }

    public void putOverridenMethods(String clazz, Set<Method> methods) {
        this.overridenMethods.put(clazz, methods);
    }

    public static OverridenJDKMethodLookup getInstance() {
        return OverridenJDKMethodLookup.LazyHolder.INSTANCE;
    }

    private static class LazyHolder {
        private static final OverridenJDKMethodLookup INSTANCE = new OverridenJDKMethodLookup();
    }
}
