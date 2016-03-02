package com.mfilipo.symantec.spe.engine;

import com.google.common.base.Optional;
import com.mfilipo.symantec.spe.engine.config.AntivirusConfig;
import com.mfilipo.symantec.spe.exception.AntivirusException;
import com.symantec.scanengine.api.Result;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Created by filipowm on 2016-02-25.
 */
@Component
public interface AntivirusScanner {

    AntivirusConfig getAntivirusConfig();

    Optional<Result> scan(ScanRequest scanRequest) throws IOException, AntivirusException;

}
