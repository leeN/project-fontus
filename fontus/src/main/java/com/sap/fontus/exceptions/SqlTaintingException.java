package com.sap.fontus.exceptions;

public class SqlTaintingException extends RuntimeException {
    public SqlTaintingException(String message) {
        super(message);
    }

    public SqlTaintingException(String message, Throwable cause) {
        super(message, cause);
    }

    public SqlTaintingException(Throwable cause) {
        super(cause);
    }
}
