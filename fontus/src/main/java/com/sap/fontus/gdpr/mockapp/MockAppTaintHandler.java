package com.sap.fontus.gdpr.mockapp;

import com.iabtcf.decoder.TCString;
import com.sap.fontus.config.Configuration;
import com.sap.fontus.config.Sink;
import com.sap.fontus.gdpr.Utils;
import com.sap.fontus.gdpr.metadata.*;
import com.sap.fontus.gdpr.metadata.registry.RequiredPurposeRegistry;
import com.sap.fontus.gdpr.metadata.simple.SimpleDataId;
import com.sap.fontus.gdpr.metadata.simple.SimpleDataSubject;
import com.sap.fontus.gdpr.metadata.simple.SimpleGdprMetadata;
import com.sap.fontus.gdpr.servlet.ReflectedCookie;
import com.sap.fontus.gdpr.servlet.ReflectedHttpServletRequest;
import com.sap.fontus.gdpr.tcf.TcfBackedGdprMetadata;
import com.sap.fontus.taintaware.IASTaintAware;
import com.sap.fontus.taintaware.shared.IASTaintSource;
import com.sap.fontus.taintaware.shared.IASTaintSourceRegistry;
import com.sap.fontus.taintaware.unified.IASString;
import com.sap.fontus.taintaware.unified.IASTaintHandler;
import com.sap.fontus.utils.UnsafeUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class MockAppTaintHandler extends IASTaintHandler {



    private static IASTaintAware setTaint(IASTaintAware taintAware, Object parent, Object[] parameters, int sourceId, String callerFunction) {
        IASTaintSource source = IASTaintSourceRegistry.getInstance().get(sourceId);

        System.out.println("FONTUS: Source: " + source);
        System.out.println("        taintAware: " + taintAware);
        System.out.println("        Caller Type:" + parent);
        System.out.println("        Input Parameters: " + Arrays.toString(parameters));
        if (parameters != null) {
            for (int i = 0; i < parameters.length; i++) {
                System.out.println("                  " + i + ": " + parameters[i].toString());
            }
        }

        // This might not work as we relocate the HttpServletRequest object...
        ReflectedHttpServletRequest servlet = new ReflectedHttpServletRequest(parent);
        System.out.println("URL: " + servlet.getRequestURL());

        ReflectedCookie[] cookies = servlet.getCookies();
        System.out.println("Cookies: " + Arrays.toString(cookies));
        if (cookies != null) {
            for (ReflectedCookie cookie : cookies) {
                System.out.println(cookie);
            }
        }

        IASString euconsentName = IASString.fromString("euconsent");
        IASString euconsentV2Name = IASString.fromString("euconsent_v2");
        TCString vendorConsent = null;
        if (cookies != null) {
            for (ReflectedCookie cookie : cookies) {
                if (cookie != null) {
                    // Make sure v2 is given priority
                    if (cookie.getName().equals(euconsentV2Name)) {
                        vendorConsent = TCString.decode(cookie.getValue().getString());
                        break;
                    } else if (cookie.getName().equals(euconsentName)) {
                        vendorConsent = TCString.decode(cookie.getValue().getString());
                        break;
                    }
                }
            }
        }
        if (vendorConsent != null) {
            System.out.println("TCF Cookie: " + vendorConsent);
            GdprMetadata metadata = new TcfBackedGdprMetadata(vendorConsent);
            System.out.println("Metadata: " + metadata);
        } else {
            System.out.println("No euconsent Cookie found, try this one: BOEFEAyOEFEAyAHABDENAI4AAAB9vABAASA");
        }
        //taintAware.setTaint(new IASBasicMetadata(source));
        return taintAware;
    }

    /**
     * The taint method can be used as a taintHandler for a given taint source
     * @param object The object to be tainted
     * @param sourceId The ID of the taint source function
     * @return The tainted object
     *
     * This snippet of XML can be added to the source:
     *
     * <pre>
     * {@code
     * <tainthandler>
     *     <opcode>184</opcode>
     *     <owner>com/sap/fontus/gdpr/handler/GdprTaintHandler</owner>
     *     <name>taint</name>
     *     <descriptor>(Ljava/lang/Object;Ljava/lang/Object;[Ljava/lang/Object;ILjava/lang/String;)Ljava/lang/Object;</descriptor>
     *     <interface>false</interface>
     * </tainthandler>
     * }
     * </pre>
     *
     */
    public static Object taint(Object object, Object parent, Object[] parameters, int sourceId, String callerFunction) {
        return IASTaintHandler.taint(object, parent, parameters, sourceId, callerFunction, MockAppTaintHandler::setTaint);
    }

    public static Object[] signUp(Object instance, Object[] parameters, int sourceId, String callerFunction) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        System.out.println("        Instance Type:" + instance);
        System.out.println("        Caller:" + callerFunction);
        System.out.println("        Caller Type:" + instance);
        System.out.println("        Input Parameters: " + Arrays.toString(parameters));
        if (parameters != null) {
            for (int i = 0; i < parameters.length; i++) {
                System.out.println("                  " + i + ": " + parameters[i].toString());
            }
        }


        IASString username = (IASString) invokeGetter(parameters[0], "getUsername");
        IASString email = (IASString) invokeGetter(parameters[0], "getEmail");

        ReflectedHttpServletRequest request = new ReflectedHttpServletRequest(parameters[1]);
        DataSubject ds = new SimpleDataSubject(username.getString());
        Collection<AllowedPurpose> allowed = Utils.getPurposesFromRequest(request);
        GdprMetadata metadata = new SimpleGdprMetadata(
                allowed,
                ProtectionLevel.Normal,
                ds,
                new SimpleDataId(),
                true,
                true,
                Identifiability.NotExplicit);
        System.out.printf("Tainting username: '%s'%n", username.getString());
        username.setTaint(new GdprTaintMetadata(sourceId, metadata));
        System.out.printf("Tainting enail: '%s'%n", email.getString());
        email.setTaint(new GdprTaintMetadata(sourceId, metadata));
        Method setInterests = parameters[0].getClass().getMethod("setInterests", List.class);
        UnsafeUtils.setAccessible(setInterests);
        List<IASString> interests = (List<IASString>) invokeGetter(parameters[0], "getInterests");
        for(IASString interest : interests) {
            System.out.printf("Tainting interest: '%s'%n", interest.toString());
            interest.setTaint(new GdprTaintMetadata(sourceId, metadata));
        }
        setInterests.invoke(parameters[0], interests);
        return parameters;
    }
    public static Object checkInterests(Object object, Object instance, String sinkFunction, String sinkName, String callerFunction) {
        List<IASString> interests = (List<IASString>) object;
        List<IASString> validInterests = new ArrayList<>(interests.size());
        Sink sink = Configuration.getConfiguration().getSinkConfig().getSinkForFqn(sinkFunction);
        RequiredPurposes requiredPurposes = RequiredPurposeRegistry.getPurposeFromSink(sink);
        for(IASString interest : interests) {
            if(!Utils.checkPolicyViolation(requiredPurposes, interest)) {
                validInterests.add(interest);
            }
        }
        return validInterests;
    }
    private static Object invokeGetter(Object obj, String name) throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {
        Method method = obj.getClass().getMethod(name);
        UnsafeUtils.setAccessible(method);
        return method.invoke(obj);
    }
}
