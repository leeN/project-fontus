import java.util.regex.Pattern;

final class Constants {
    static final Pattern strPattern = Pattern.compile("Ljava/lang/String\\b");

    /**
     * The fully qualified name of the String class
     */
    static final String String = "java/lang/String";
    /**
     * The fully qualified name of the StringBuilder class
     */
    static final String StringBuilder = "java/lang/StringBuilder";
    /**
     * The type of our taint-aware String
     */
    static final String TString = "IASString";
    /**
     * The bytecode descriptor of our taint aware string
     */
    static final String TStringDesc = "LIASString";
    /**
     * The bytecode descriptor of an array of our taint aware string
     */
    static final String TStringArrayDesc = "[LIASString;";

    static final Pattern strBuilderPattern = Pattern.compile("Ljava/lang/StringBuilder\\b");
    /**
     * The type of our taint-aware StringBuilder
     */
    static final String TStringBuilder = "IASStringBuilder";
    /**
     * The bytecode descriptor of our taint aware StringBuilder
     */
    static final String TStringBuilderDesc = "LIASStringBuilder";

    /**
     * Constructor name
     */
    static final String Init = "<init>";

    /**
     * Autogenerated name of the main wrapper function
     */
    static final String MainWrapper = "$main";

    /**
     * Descriptor of the untainted init/constructor method.
     */
    static final String TStringInitUntaintedDesc = "(Ljava/lang/String;)V";

    /**
     * Name of the method that converts taint-aware Strings to regular ones
     */
    static final String TStringToStringName = "getString";
    /**
     * Descriptor of the taint-aware to regular String conversion method
     */
    static final String TStringToStringDesc = "()Ljava/lang/String;";

    private Constants() {}

}
