package com.sap.fontus.taintaware.shared;

import com.sap.fontus.config.Configuration;
import com.sap.fontus.instrumentation.InstrumentationHelper;
import com.sap.fontus.utils.Utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class IASInstrumenterInputStream extends ByteArrayInputStream {
    private static final InstrumentationHelper instrumentationHelper = new InstrumentationHelper(Configuration.getConfiguration().getTaintStringConfig());

    public IASInstrumenterInputStream(InputStream inputStream) {
        super(readAndInstrument(inputStream).getBytes(StandardCharsets.UTF_8));
    }

    private static String readAndInstrument(InputStream is) {
        BufferedReader br = new BufferedReader(new InputStreamReader(is));
        return br.lines()
                .map(Utils::dotToSlash)
                .map(instrumentationHelper::instrumentQN)
                .map(Utils::slashToDot)
                .collect(Collectors.joining("\n"));
    }
}
