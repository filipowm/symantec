package com.mfilipo.symantec.spe.engine;

import com.google.common.base.Optional;
import com.mfilipo.symantec.spe.engine.config.AntivirusConfig;
import com.mfilipo.symantec.spe.event.AntivirusEvent;
import com.mfilipo.symantec.spe.event.AntivirusListener;
import com.mfilipo.symantec.spe.event.ScanFailureEvent;
import com.mfilipo.symantec.spe.event.ScanSuccessEvent;
import com.mfilipo.symantec.spe.exception.AntivirusException;
import com.mfilipo.symantec.spe.exception.ScanFailedException;
import com.mfilipo.symantec.spe.utils.FileUtils;
import com.mfilipo.symantec.spe.utils.Validateable;
import com.symantec.scanengine.api.Result;
import com.symantec.scanengine.api.ScanEngine;
import com.symantec.scanengine.api.ScanException;
import com.symantec.scanengine.api.StreamScanRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Created by filipowm on 2016-02-26.
 */
@Component
public class SymantecAntivirusScanner implements AntivirusScanner {

    private static final Logger LOG = LoggerFactory.getLogger(SymantecAntivirusScanner.class);
    private final AntivirusConfig antivirusConfig;
    private final ScanEngine engine;
    private EventDispatcher eventDispatcher;

    @Autowired
    public SymantecAntivirusScanner(AntivirusConfig antivirusConfig) {
        this(antivirusConfig, Collections.emptyList());
    }

    @Autowired
    public SymantecAntivirusScanner(AntivirusConfig antivirusConfig, AntivirusListener... antivirusListeners) {
        this(antivirusConfig, Arrays.asList(antivirusListeners));
    }

    @Autowired
    public SymantecAntivirusScanner(AntivirusConfig antivirusConfig, List<AntivirusListener> antivirusListeners) {
        Validateable.validate(antivirusConfig);

        this.antivirusConfig = antivirusConfig;
        eventDispatcher = new EventDispatcher(antivirusListeners);
        try {
            LOG.debug("Initializing Symantec ScanEngine");
            this.engine = prepareScanEngine();
            LOG.debug("Symantec ScanEngine initialized");
        } catch (ScanException e) {
            LOG.error("Scan engine initialization failed with parameters:\nhost: {}\nport: {}\nreadWriteTime: {}\nfailRetryTime: {}",
                    antivirusConfig.getHost(), antivirusConfig.getPort(), antivirusConfig.getReadWriteTime(), antivirusConfig.getFailRetryTime());
            LOG.error(e.getMessage(), e);
            throw new AntivirusException("Scan engine initialization failed", e);
        }
    }

    private ScanEngine prepareScanEngine() throws ScanException {
        LOG.debug("ScanEngine configuration:\nhost: {}\nport: {}\nreadWriteTime: {}\nfailRetryTime: {}",
                antivirusConfig.getHost(), antivirusConfig.getPort(), antivirusConfig.getReadWriteTime(), antivirusConfig.getFailRetryTime());
        ScanEngine.ScanEngineInfo engineInfo = new ScanEngine.ScanEngineInfo(antivirusConfig.getHost(), antivirusConfig.getPort());
        return ScanEngine.createScanEngine(Collections.singletonList(engineInfo), antivirusConfig.getReadWriteTime(), antivirusConfig.getFailRetryTime());
    }

    @Override
    public AntivirusConfig getAntivirusConfig() {
        return antivirusConfig;
    }

    @Override
    public Optional<Result> scan(ScanRequest scanRequest) throws AntivirusException, IOException {
        Validateable.validate(scanRequest);
        Result result = null;
        if(antivirusConfig.isEnabled()) {
//            init();
            File tmpFile = null;
            try {
                tmpFile = FileUtils.createTempFile();
                StreamScanRequest sr = engine.createStreamScanRequest(
                        scanRequest.getInput().getAbsolutePath(),
                        tmpFile.getAbsolutePath(),
                        scanRequest.getOutput(),
                        antivirusConfig.getPolicy(),
                        antivirusConfig.isExtendedInfo()
                );
                result = sr.scanFile();
                eventDispatcher.dispatch(new ScanSuccessEvent(scanRequest, result));
            } catch (ScanException | IOException e) {
                LOG.error("Error while scanning file for infections", e);
                ScanFailedException exception = new ScanFailedException("Error while scanning file for infections", e, scanRequest);
                eventDispatcher.dispatch(new ScanFailureEvent(scanRequest, exception));
                throw exception;
            } finally {
                if (scanRequest.isCleanupAfterScan()) {
                    scanRequest.getInput().delete();
                }
                if (tmpFile != null) {
                    tmpFile.delete();
                }
            }
        }
        return Optional.fromNullable(result);
    }

    private static class EventDispatcher {
        private final List<AntivirusListener> antivirusListeners = new ArrayList<>();

        EventDispatcher(List<AntivirusListener> listeners) {
            this.antivirusListeners.addAll(listeners);
        }

        void dispatch(AntivirusEvent event) {
            for (AntivirusListener listener : antivirusListeners) {
                listener.onApplicationEvent(event);
            }
        }
    }
}
