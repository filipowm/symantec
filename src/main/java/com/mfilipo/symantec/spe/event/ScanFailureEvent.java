package com.mfilipo.symantec.spe.event;

import com.symantec.scanengine.api.ErrorCode;
import com.symantec.scanengine.api.ScanException;

import java.io.File;

/**
 * Created by filipowm on 2016-03-01.
 */
public class ScanFailureEvent extends AntivirusEvent {

    private final ScanException exception;

    public ScanFailureEvent(File source, ScanException exception) {
        super(source);
        this.exception = exception;
    }

    public ScanFailureEvent(String source, ScanException exception) {
        super(source);
        this.exception = exception;
    }

    public ScanException getException() {
        return exception;
    }

    public ErrorCode getErrorCode() {
        return exception.getExceptionCode();
    }
}
