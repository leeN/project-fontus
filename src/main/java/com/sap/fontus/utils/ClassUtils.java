package com.sap.fontus.utils;

import com.sap.fontus.config.Configuration;
import com.sap.fontus.utils.lookups.CombinedExcludedLookup;
import org.objectweb.asm.Type;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;

public class ClassUtils {
    public static CombinedExcludedLookup combinedExcludedLookup = new CombinedExcludedLookup(null);
    private static final ClassFinder classFinder = InstrumentationFactory.createClassFinder();

    public static Class<?> findLoadedClass(String internalName) {
        Class<?> loaded = classFinder.findClass(Utils.slashToDot(internalName));
        if (loaded == null && combinedExcludedLookup.isJdkClass(internalName)) {
            try {
                loaded = Class.forName(Type.getObjectType(internalName).getClassName());
            } catch (ClassNotFoundException e) {
                Utils.logException(e);
            }
        }
        return loaded;
    }

    public static Class<?> findLoadedClass(String internalName, ClassLoader loader) {
        Class<?> loaded = classFinder.findClass(Utils.slashToDot(internalName));
        if (loaded == null && new CombinedExcludedLookup(loader).isJdkClass(internalName)) {
            try {
                loaded = Class.forName(Type.getObjectType(internalName).getClassName(), false, loader);
            } catch (ClassNotFoundException e) {
                Utils.logException(e);
            }
        }
        return loaded;
    }

    public static InputStream getClassInputStream(String internalName, ClassLoader loader) {
        InputStream resource = InstrumentationFactory.createClassResolver(loader).resolve(internalName);
        if (resource != null) {
            return resource;
        }
        throw new RuntimeException("Resource for " + internalName + " couldn't be found");
    }

    public static boolean isInterface(String internalName) {
        return ClassUtils.isInterface(internalName, null);
    }

    public static boolean isInterface(int access) {
        return ((access & Opcodes.ACC_INTERFACE) == Opcodes.ACC_INTERFACE);
    }

    public static boolean isInterface(byte[] bytes) {
        return ClassUtils.isInterface(new ClassReader(bytes).getAccess());
    }

    public static boolean isInterface(String internalName, ClassLoader loader) {
        try {
            return ClassUtils.isInterface(new ClassReader(getClassInputStream(internalName, loader)).getAccess());
        } catch (IOException e) {
            if (Configuration.isLoggingEnabled()) {
                System.err.println("Could not resolve class " + internalName + " for isInterface checking");
            }
        }
        return false;
    }

    public static Class<?> arrayType(Class<?> cls) {
        return Array.newInstance(cls, 0).getClass();
    }
}
