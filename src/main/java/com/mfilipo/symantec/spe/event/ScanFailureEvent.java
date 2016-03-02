package com.mfilipo.symantec.spe.event;

import com.mfilipo.symantec.spe.engine.ScanRequest;
import com.mfilipo.symantec.spe.exception.ScanFailedException;
import com.symantec.scanengine.api.ErrorCode;

/**
 * Created by filipowm on 2016-03-01.
 */
public class ScanFailureEvent extends AntivirusEvent {

    private final ScanFailedException exception;

    public ScanFailureEvent(ScanRequest request, ScanFailedException exception) {
        super(request);
        this.exception = exception;
    }

    public ScanFailedException getException() {
        return exception;
    }

    public ErrorCode getErrorCode() {
        return exception.getErrorCode().orNull();
    }

    public ScanRequest getScanRequest() {
        return (ScanRequest) source;
    }
}
