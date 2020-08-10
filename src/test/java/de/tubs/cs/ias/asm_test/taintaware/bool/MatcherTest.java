package de.tubs.cs.ias.asm_test.taintaware.bool;

import de.tubs.cs.ias.asm_test.config.Configuration;
import de.tubs.cs.ias.asm_test.config.TaintMethod;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MatcherTest {

    @BeforeAll
    public static void init() {
        Configuration.setTestConfig(TaintMethod.BOOLEAN);
    }

    /**
     * Regression for luindex benchmark bug
     */
    @Test
    public void matcherRegression() {
        IASPattern pattern = IASPattern.compile(new IASString("_[a-z0-9]+(_.*)?\\..*"));
        IASMatcher m = pattern.matcher("");
        IASString s = new IASString("_0_Lucene50_0.doc");

        IASMatcher m1 = m.reset(s);
        boolean matches = m.matches();

        assertEquals(m, m1);
        assertTrue(matches);
    }
}
