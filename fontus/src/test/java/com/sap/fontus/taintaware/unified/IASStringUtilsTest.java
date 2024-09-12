package com.sap.fontus.taintaware.unified;

import com.sap.fontus.config.Configuration;
import com.sap.fontus.config.TaintMethod;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IASStringUtilsTest {

    @BeforeAll
    static void setup() {
        Configuration.setTestConfig(TaintMethod.defaultTaintMethod());
    }

    @Test
    void testConvertObjectString() {
        String s = "test";
        Object o = IASStringUtils.convertObject(s);
        assertInstanceOf(IASString.class, o);
    }

    @Test
    void testConvertObjectIASString() {
        String s = "test";
        Object o = IASStringUtils.convertObject(IASString.fromString(s));
        assertInstanceOf(IASString.class, o);
    }

    @Test
    void testConvertObjectOther() {
        List<Integer> l = new ArrayList<>();
        Object o = IASStringUtils.convertObject(l);
        assertInstanceOf(List.class, o);
    }

    @Test
    void testConvertTObjectString() {
        String s = "test";
        Object o = IASStringUtils.convertTObject(s);
        assertInstanceOf(String.class, o);
    }

    @Test
    void testConvertTObjectIASString() {
        String s = "test";
        Object o = IASStringUtils.convertTObject(IASString.fromString(s));
        assertInstanceOf(String.class, o);
    }

    @Test
    void testConvertTObjectOther() {
        List<Integer> l = new ArrayList<>();
        Object o = IASStringUtils.convertTObject(l);
        assertInstanceOf(List.class, o);
    }

    @Test
    void getEnv() {
        Map<String, String> originalEnv = System.getenv();
        Map<IASString, IASString> taintedEnv = IASStringUtils.getenv();
        for (Map.Entry<IASString, IASString> entry : taintedEnv.entrySet()) {
            String key = entry.getKey().toString();
            String value = entry.getValue().toString();
            assertTrue(originalEnv.containsKey(key));
            assertEquals(originalEnv.get(key), value);
        }
        assertEquals(taintedEnv.size(), originalEnv.size());
    }
}
