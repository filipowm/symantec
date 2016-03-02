package com.mfilipo.symantec.spe.exception;

/**
 * Created by filipowm on 2016-02-25.
 */
public class AntivirusException extends RuntimeException {

    public AntivirusException(String message) {
        super(message);
    }

    public AntivirusException(Throwable cause) {
        super(cause);
    }

    public AntivirusException(String message, Throwable cause) {
        super(message, cause);
    }

}
