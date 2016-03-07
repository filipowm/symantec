package com.mfilipo.symantec.spe.event;

import com.mfilipo.symantec.spe.engine.ScanRequest;
import com.symantec.scanengine.api.Result;
import com.symantec.scanengine.api.ResultStatus;
import com.symantec.scanengine.api.ThreatInfo;

import java.util.Arrays;
import java.util.List;

/**
 * Created by filipowm on 2016-03-01.
 */
public class ScanSuccessEvent extends AntivirusScanEvent {

    private final Result result;

    public ScanSuccessEvent(ScanRequest request, Result result) {
        super(request);
        this.result = result;
    }

    public ResultStatus getResultStatus() {
        return result.getStatus();
    }

    public boolean isLicenceCorrect() {
        return getResultStatus() != ResultStatus.NO_AV_LICENSE;
    }

    public boolean isServerError() {
        return getResultStatus() == ResultStatus.INTERNAL_SERVER_ERROR;
    }

    public boolean isFileTooLarge() {
        return getResultStatus() == ResultStatus.FILE_SIZE_TOO_LARGE;
    }

    public boolean hasFileAccessFailed() {
        return getResultStatus() == ResultStatus.FILE_ACCESS_FAILED;
    }

    public boolean isInfected() {
        return result.getTotalInfection() == 0;
    }

    public Result getResult() {
        return result;
    }

    public List<ThreatInfo> getThreats() {
        return Arrays.asList(result.getThreatInfo());
    }
}
