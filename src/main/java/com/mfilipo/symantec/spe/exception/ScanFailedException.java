package com.mfilipo.symantec.spe.exception;

import com.google.common.base.Optional;
import com.mfilipo.symantec.spe.engine.ScanRequest;
import com.symantec.scanengine.api.ErrorCode;
import com.symantec.scanengine.api.ScanException;

/**
 * Created by filipowm on 2016-03-02.
 */
public class ScanFailedException extends AntivirusException {

    private final ScanRequest scanRequest;

    public ScanFailedException(String message, ScanRequest scanRequest) {
        super(message);
        this.scanRequest = scanRequest;
    }

    public ScanFailedException(ScanException cause, ScanRequest scanRequest) {
        super(cause);
        this.scanRequest = scanRequest;
    }

    public ScanFailedException(String message, Throwable cause, ScanRequest scanRequest) {
        super(message, cause);
        this.scanRequest = scanRequest;
    }

    public ScanRequest getScanRequest() {
        return scanRequest;
    }

    public Optional<ErrorCode> getErrorCode() {
        return getCause() instanceof ScanException ? Optional.of(((ScanException) getCause()).getExceptionCode()) : Optional.absent();
    }
}
