package com.mfilipo.symantec.spe.engine;

import com.google.common.base.Optional;
import com.mfilipo.symantec.spe.engine.config.AntivirusConfig;
import com.mfilipo.symantec.spe.event.AntivirusEvent;
import com.mfilipo.symantec.spe.event.AntivirusListener;
import com.mfilipo.symantec.spe.event.ScanFailureEvent;
import com.mfilipo.symantec.spe.event.ScanSuccessEvent;
import com.mfilipo.symantec.spe.exception.AntivirusException;
import com.symantec.scanengine.api.Result;
import com.symantec.scanengine.api.ScanEngine;
import com.symantec.scanengine.api.ScanException;
import com.symantec.scanengine.api.StreamScanRequest;
import org.apache.commons.io.output.NullOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Created by filipowm on 2016-02-26.
 */
@Component
public class SymantecAntivirusScanner implements AntivirusScanner {

    private static final Logger LOG = LoggerFactory.getLogger(SymantecAntivirusScanner.class);
    private final AntivirusConfig antivirusConfig;
    private final ScanEngine engine;
    private final EventDispatcher eventDispatcher;

    @Autowired
    public SymantecAntivirusScanner(AntivirusConfig antivirusConfig) {
        this(antivirusConfig, Collections.emptyList());
    }

    @Autowired
    public SymantecAntivirusScanner(AntivirusConfig antivirusConfig, AntivirusListener... listeners) {
        this(antivirusConfig, Arrays.asList(listeners));
    }

    @Autowired
    public SymantecAntivirusScanner(AntivirusConfig antivirusConfig, List<AntivirusListener> listeners) {
        this.antivirusConfig = antivirusConfig;
        eventDispatcher = new EventDispatcher(listeners);
        try {
            LOG.debug("Initializing Symantec ScanEngine");
            this.engine = prepareScanEngine();
            LOG.debug("Symantec ScanEngine initialized");
        } catch (ScanException e) {
            LOG.error("Scan engine initialization failed with parameters:\nhost: {}\nport: {}\nreadWriteTime: {}\nfailRetryTime: {}",
                    antivirusConfig.getHost(), antivirusConfig.getPort(), antivirusConfig.getReadWriteTime(), antivirusConfig.getFailRetryTime());
            LOG.error(e.getMessage(), e);
            throw new AntivirusException();
        }
    }

    private ScanEngine prepareScanEngine() throws ScanException {
        LOG.error("ScanEngine configuration:\nhost: {}\nport: {}\nreadWriteTime: {}\nfailRetryTime: {}",
                antivirusConfig.getHost(), antivirusConfig.getPort(), antivirusConfig.getReadWriteTime(), antivirusConfig.getFailRetryTime());
        ScanEngine.ScanEngineInfo engineInfo = new ScanEngine.ScanEngineInfo(antivirusConfig.getHost(), antivirusConfig.getPort());
        return ScanEngine.createScanEngine(Collections.singletonList(engineInfo), antivirusConfig.getReadWriteTime(), antivirusConfig.getFailRetryTime());
    }

    @Override
    public AntivirusConfig getAntivirusConfig() {
        return antivirusConfig;
    }

    @Override
    public Optional<Result> scan(File file) throws IOException {
        return scan(file, new NullOutputStream());
    }

    @Override
    public Optional<Result> scan(File file, OutputStream saveStream) throws IOException {
        Result result = null;
        if(antivirusConfig.isEnabled()) {
//            init();
            File tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
            try {
                StreamScanRequest scanRequest = engine.createStreamScanRequest(
                        file.getAbsolutePath(),
                        tmpFile.getAbsolutePath(),
                        saveStream,
                        antivirusConfig.getPolicy(),
                        antivirusConfig.isExtendedInfo()
                );

                result = scanRequest.scanFile();
                eventDispatcher.dispatch(new ScanSuccessEvent(file, result));
            } catch (ScanException e) {
                LOG.error("Error while scanning file for infections", e);
                eventDispatcher.dispatch(new ScanFailureEvent(file, e));
            } finally {
                tmpFile.delete();
            }
        }
        return Optional.fromNullable(result);
    }

    public Optional<Result> scan(File file, OutputStream saveStream, boolean removeAfterScan) throws IOException {
        Result result = null;
        if(antivirusConfig.isEnabled()) {
//            init();
            File tmpFile = File.createTempFile(UUID.randomUUID().toString(), ".tmp");
            try {
                StreamScanRequest scanRequest = engine.createStreamScanRequest(
                        file.getAbsolutePath(),
                        tmpFile.getAbsolutePath(),
                        saveStream,
                        antivirusConfig.getPolicy(),
                        antivirusConfig.isExtendedInfo()
                );

                result = scanRequest.scanFile();
                eventDispatcher.dispatch(new ScanSuccessEvent(file, result));
            } catch (ScanException e) {
                LOG.error("Error while scanning file for infections", e);
                eventDispatcher.dispatch(new ScanFailureEvent(file, e));
            } finally {
                if (removeAfterScan) {
                    file.delete();
                }
                tmpFile.delete();
            }
        }
        return Optional.fromNullable(result);
    }

    @Override
    public Optional<Result> scan(File file, File saveFile) throws IOException {
        return scan(file, new FileOutputStream(saveFile));
    }

    @Override
    public Optional<Result> scan(File file, String savePath) throws IOException {
        return scan(file, new FileOutputStream(savePath));
    }

    @Override
    public Optional<Result> scan(String path) throws IOException {
        return scan(new File(path));
    }

    @Override
    public Optional<Result> scan(String path, OutputStream saveStream) throws IOException {
        return scan(new File(path), saveStream);
    }

    @Override
    public Optional<Result> scan(String path, File saveFile) throws IOException {
        return scan(new File(path), saveFile);
    }

    @Override
    public Optional<Result> scan(String path, String savePath) throws IOException {
        return scan(new File(path), savePath);
    }

    @Override
    public Optional<Result> scan(InputStream stream) {
        return null;
    }

    @Override
    public Optional<Result> scan(InputStream stream, OutputStream saveStream) {
        return scan(FileUtils.toTempFile(stream));
    }

    @Override
    public Optional<Result> scan(InputStream stream, File saveFile) {
        return null;
    }

    @Override
    public Optional<Result> scan(InputStream stream, String savePath) {
        return null;
    }

    @Override
    public Optional<Result> scan(byte[] bytes) {
        return null;
    }

    @Override
    public Optional<Result> scan(byte[] bytes, OutputStream saveStream) {
        return null;
    }

    @Override
    public Optional<Result> scan(byte[] bytes, File saveFile) {
        return null;
    }

    @Override
    public Optional<Result> scan(byte[] bytes, String savePath) {
        return null;
    }

    private class EventDispatcher {
        private final List<AntivirusListener> antivirusListeners;

        EventDispatcher(List<AntivirusListener> listeners) {
            this.antivirusListeners = listeners;
        }

        void dispatch(AntivirusEvent event) {
            for (AntivirusListener listener : antivirusListeners) {
                listener.onApplicationEvent(event);
            }
        }
    }
}
