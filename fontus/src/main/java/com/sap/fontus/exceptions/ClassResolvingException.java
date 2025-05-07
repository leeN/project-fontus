package com.sap.fontus.exceptions;

public class ClassResolvingException extends RuntimeException {
    public ClassResolvingException(String message) {
        super(message);
    }

    public ClassResolvingException(String message, Throwable cause) {
        super(message, cause);
    }

    public ClassResolvingException(Throwable cause) {
        super(cause);
    }
}
