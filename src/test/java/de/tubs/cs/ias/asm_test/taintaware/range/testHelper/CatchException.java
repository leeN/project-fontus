package de.tubs.cs.ias.asm_test.taintaware.range.testHelper;

/**
 * Created by d059349 on 16.07.17.
 */
public class CatchException {

    public interface ThrowingFunction {
        void doAction();
    }

    public static Throwable catchException(ThrowingFunction func) {
        Throwable thrown = null;

        try {
            func.doAction();
        } catch (Throwable err) {
            thrown = err;
        }

        if (thrown == null) {
            throw new RuntimeException("No exception thrown!");
        }

        return thrown;
    }

}
