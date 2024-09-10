package com.sap.fontus.instrumentation;

import com.sap.fontus.instrumentation.compat.SqliteCollation;
import com.sap.fontus.instrumentation.compat.SqliteDB;
import com.sap.fontus.instrumentation.compat.SqliteNativeDB;

import java.util.concurrent.ConcurrentHashMap;

public final class CompatHelper {
    private final ConcurrentHashMap<String, CompatImplementation> implementations;

    private CompatHelper() {
        this.implementations = new ConcurrentHashMap<>();
        // TODO: Replace with generic version based on reflection?
        this.registerImplementation( new SqliteCollation());
        this.registerImplementation( new SqliteNativeDB());
        this.registerImplementation( new SqliteDB());
    }

    public void registerImplementation(CompatImplementation implementation) {
        this.implementations.put(implementation.getAffects(), implementation);
    }

    public interface CompatImplementation {
        String getAffects();
        void apply(String owner, MethodVisitorCreator methodVisitorCreator);
    }

    public static CompatHelper getInstance() {
        return CompatHelper.LazyHolder.INSTANCE;
    }

    private static class LazyHolder {
        private static final CompatHelper INSTANCE = new CompatHelper();
    }

    public void createCompatProxies(String owner, MethodVisitorCreator methodVisitorCreator) {
        CompatImplementation implementation = this.implementations.get(owner);
        if(implementation != null) {
            implementation.apply(owner, methodVisitorCreator);
        }

    }


}