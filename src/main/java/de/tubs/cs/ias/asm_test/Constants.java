package de.tubs.cs.ias.asm_test;

import de.tubs.cs.ias.asm_test.asm.Descriptor;
import de.tubs.cs.ias.asm_test.taintaware.shared.IASCompareProxy;
import de.tubs.cs.ias.asm_test.taintaware.shared.IASTaintHandler;
import de.tubs.cs.ias.asm_test.utils.ConversionUtils;
import de.tubs.cs.ias.asm_test.utils.Utils;

import java.util.Properties;
import java.util.regex.Pattern;

public final class Constants {
    public static final String AGENT_DELIMITER = ",";

    public static final String ConversionUtilsQN = Utils.getInternalName(ConversionUtils.class);
    public static final String ConversionUtilsToConcreteName;
    public static final String ConversionUtilsToConcreteDesc;
    public static final String ConversionUtilsToOrigName;
    public static final String ConversionUtilsToOrigDesc;
    public static final String TaintHandlerQN;
    public static final String TaintHandlerTaintName;
    public static final String TaintHandlerTaintDesc;
    public static final String TaintHandlerCheckTaintName;
    public static final String TaintHandlerCheckTaintDesc;
    public static final String PropertyDesc;
    public static final String PropertyQN;
    public static final String JDK_INHERITANCE_BLACKLIST_FILENAME = "jdk_inheritance_blacklist.csv";
    public static final String CompareProxyQN = Utils.getInternalName(IASCompareProxy.class);
    public static final String CompareProxyEqualsName = "compareRefEquals";
    public static final String CompareProxyEqualsDesc;
    public static final String UNTAINTED_METHOD_NAME = "untainted";
    public static final String UNTAINTED_METHOD_PATH = "untainted/";

    static {
        try {
            ConversionUtilsToConcreteName = ConversionUtils.class.getMethod("convertToConcrete", Object.class).getName();
            ConversionUtilsToConcreteDesc = Descriptor.parseMethod(ConversionUtils.class.getMethod("convertToConcrete", Object.class)).toDescriptor();
            ConversionUtilsToOrigName = ConversionUtils.class.getMethod("convertToOrig", Object.class).getName();
            ConversionUtilsToOrigDesc = Descriptor.parseMethod(ConversionUtils.class.getMethod("convertToOrig", Object.class)).toDescriptor();
            TaintHandlerQN = Utils.getInternalName(IASTaintHandler.class);
            TaintHandlerTaintName = IASTaintHandler.class.getMethod("taint", Object.class, int.class).getName();
            TaintHandlerTaintDesc = Descriptor.parseMethod(IASTaintHandler.class.getMethod("taint", Object.class, int.class)).toDescriptor();
            TaintHandlerCheckTaintName = IASTaintHandler.class.getMethod("checkTaint", Object.class, String.class).getName();
            TaintHandlerCheckTaintDesc = Descriptor.parseMethod(IASTaintHandler.class.getMethod("checkTaint", Object.class, String.class)).toDescriptor();
            CompareProxyEqualsDesc = Descriptor.parseMethod(IASCompareProxy.class.getMethod("compareRefEquals", Object.class, Object.class)).toDescriptor();

            PropertyDesc = Descriptor.classNameToDescriptorName(Properties.class.getName());
            PropertyQN = Utils.getInternalName(Properties.class);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    public static final String TPropertiesToPropertiesName = "getProperties";

    /**
     * Fully qualified name of the java Object class.
     */
    public static final String ObjectQN = "java/lang/Object";

    /**
     * The fully qualified name of the String class
     */
    public static final String StringQN = "java/lang/String";

    /**
     * The fully qualified name of the Formatter class
     */
    public static final String FormatterQN = "java/util/Formatter";

    /**
     * The fully qualified name of the StringBuilder class
     */
    public static final String StringBuilderQN = "java/lang/StringBuilder";

    /**
     * The fully qualified name of the StringBuffer class
     */
    public static final String StringBufferQN = "java/lang/StringBuffer";

    /**
     * Name of the toString method.
     */
    public static final String ToString = "toString";

    /**
     * Descriptor of the java Object class
     */
    public static final String ObjectDesc = java.lang.String.format("L%s;", ObjectQN);

    /**
     * Descriptor of the java String class
     */
    public static final String StringDesc = java.lang.String.format("L%s;", StringQN);

    public static final String FormatterDesc = java.lang.String.format("L%s;", FormatterQN);

    /**
     * Descriptor of an array of regular Java Strings
     */
    public static final String StringArrayDesc = String.format("[%s", StringDesc);

    /**
     * Descriptor of the java StringBuilder class
     */
    public static final String StringBuilderDesc = java.lang.String.format("L%s;", StringBuilderQN);
    /**
     * Descriptor of the java StringBuffer class
     */
    public static final String StringBufferDesc = java.lang.String.format("L%s;", StringBufferQN);
    /**
     * Constructor name
     */
    public static final String Init = "<init>";

    /**
     * Static initializer name
     */
    public static final String ClInit = "<clinit>";

    /**
     * Autogenerated name of the main wrapper function
     */
    public static final String MainWrapper = "main";

    /**
     * Name of the method that converts taint-aware Strings to regular ones
     */
    public static final String TStringToStringName = "getString";

    /**
     * Name of the method that converts taint-aware Formatters to regular ones
     */
    public static final String TFormatterToFormatterName = "getFormatter";

    /**
     * Name of the method that converts taint-aware StringBuilders to regular ones
     */
    public static final String TStringBuilderToStringBuilderName = "getStringBuilder";

    /**
     * Name of the method that converts taint-aware StringBuffers to regular ones
     */
    public static final String TStringBufferToStringBufferName = "getStringBuffer";

    /**
     * Descriptor of the untainted init/constructor method.
     */
    public static final String TStringInitUntaintedDesc = "(Ljava/lang/String;)V";

    /**
     * Matches fully qualified String names
     */
    public static final Pattern strPattern = Pattern.compile(StringDesc);

    public static final Pattern formatterPattern = Pattern.compile(FormatterDesc);

    /**
     * Matches fully qualified StringBuilder names
     */
    public static final Pattern strBuilderPattern = Pattern.compile(StringBuilderDesc);
    /**
     * Matches fully qualified StringBuilder names
     */
    public static final Pattern strBufferPattern = Pattern.compile(StringBufferDesc);

    /**
     * Descriptor of the Java main method
     */
    public static final String MAIN_METHOD_DESC = "([Ljava/lang/String;)V";

    /**
     * Method to return taint-aware string representation from instrumented class.
     */
    public static final String TO_TSTRING = "toIASString";

    /**
     * Full name of the Java String type
     */
    public static final String STRING_FULL_NAME = "java.lang.String";

    /**
     * Full name of the Java StringBuffer type
     */
    public static final String STRINGBUFFER_FULL_NAME = "java.lang.StringBuffer";

    /**
     * Full name of the Java StringBuilder type
     */
    public static final String STRINGBUILDER_FULL_NAME = "java.lang.StringBuilder";

    public static final String AS_STRING = "asString";

    public static final String FROM_STRING = "fromString";

    /**
     * Suffix of class files.
     */
    public static final String CLASS_FILE_SUFFIX = ".class";

    /**
     * Suffix of jar files.
     */
    public static final String JAR_FILE_SUFFIX = ".jar";
    public static final String AnnotationQN = "java/lang/annotation/Annotation";
    public static final String ProxyQN = "java/lang/reflect/Proxy";

    /**
     * Suffix of json
     */
    public static final String JSON_FILE_SUFFIX = ".json";

    /**
     * Suffix of XML
     */
    public static final String XML_FILE_SUFFIX = ".xml";
    public static final String CONFIGURATION_XML_FILENAME = "configuration.xml";
    public static final String VALUE_OF = "valueOf";
    public static final String MatcherQN = "java/util/regex/Matcher";
    public static final String MatcherDesc = java.lang.String.format("L%s;", MatcherQN);
    public static final String TMatcherToMatcherName = "getMatcher";
    public static final String PatternQN = "java/util/regex/Pattern";
    public static final String PatternDesc = java.lang.String.format("L%s;", PatternQN);
    public static final String TPatternToPatternName = "getPattern";

    public static final String PACKAGE = "de.tubs.cs.ias.asm_test";

    private Constants() {
    }

    public static final String BOOLEAN_METHOD_NAME = "boolean";
    public static final String BOOLEAN_METHOD_PATH = "bool/";
    public static final String RANGE_METHOD_NAME = "range";
    public static final String RANGE_METHOD_PATH = "range/";
    public static final String LAZY_COMPLEX_METHOD_NAME = "lazycomplex";
    public static final String LAZY_COMPLEX_METHOD_PATH = "lazycomplex/";
    public static final String LAZY_BASIC_METHOD_NAME = "lazybasic";
    public static final String LAZY_BASIC_METHOD_PATH = "lazybasic/";
    public static final String ARRAY_METHOD_NAME = "array";
    public static final String ARRAY_METHOD_PATH = "array/";
    public static final int JAVA_VERSION = getVersion();

    private static int getVersion() {
        String version = System.getProperty("java.version");
        if (version.startsWith("1.")) {
            version = version.substring(2, 3);
        } else {
            int dot = version.indexOf(".");
            if (dot != -1) {
                version = version.substring(0, dot);
            }
        }
        return Integer.parseInt(version);
    }
}
