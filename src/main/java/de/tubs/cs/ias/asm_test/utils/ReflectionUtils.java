package de.tubs.cs.ias.asm_test.utils;


import de.tubs.cs.ias.asm_test.Constants;
import jdk.internal.reflect.ConstructorAccessor;
import jdk.internal.reflect.MethodAccessor;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;

public class ReflectionUtils {
    private static Class MethodAccessor;
    private static Class ConstructorAccessor;

    @SuppressWarnings("Since15")
    public static Class getCallerClass() {
        if (Constants.JAVA_VERSION >= 9) {
            return StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE).walk((Function<Stream<StackWalker.StackFrame>, Class>) stackFrameStream -> stackFrameStream.filter(new Predicate<StackWalker.StackFrame>() {
                private int counter = 0;

                @Override
                public boolean test(StackWalker.StackFrame stackFrame) {
                    counter++;
                    return counter == 3;
                }
            }).findFirst().get().getDeclaringClass());
        }
        StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
        Class caller = null;
        for (int i = 3; i < stackTraceElements.length; i++) {
            String currentCallerName = stackTraceElements[i].getClassName();
            try {
                Class currentCaller = Class.forName(currentCallerName, false, Thread.currentThread().getContextClassLoader());
                if (!isReflectionFrame(currentCaller)) {
                    caller = currentCaller;
                    break;
                }
            } catch (ClassNotFoundException ignored) {
            }
        }
        if (caller == null) {
            throw new RuntimeException("Caller couldn't be found");
        }
        return caller;
    }

    private static boolean isReflectionFrame(Class c) {
        if (Constants.JAVA_VERSION < 9 && (MethodAccessor == null || ConstructorAccessor == null)) {
            try {
                MethodAccessor = Class.forName("sun.reflect.MethodAccessor");
                ConstructorAccessor = Class.forName("sun.reflect.ConstructorAccessor");
            } catch (ClassNotFoundException e) {
                try {
                    MethodAccessor = Class.forName("jdk.internal.reflect.MethodAccessor");
                    ConstructorAccessor = Class.forName("jdk.internal.reflect.ConstructorAccessor");
                } catch (ClassNotFoundException classNotFoundException) {
                    throw new RuntimeException("Couldnt find MethodAccessor or ConstructorAccessor class");
                }
            }
        }
        return c == Method.class ||
                c == Constructor.class ||
                MethodAccessor.isAssignableFrom(c) ||
                ConstructorAccessor.isAssignableFrom(c) ||
                c.getName().startsWith("java.lang.invoke.LambdaForm");

    }
}
