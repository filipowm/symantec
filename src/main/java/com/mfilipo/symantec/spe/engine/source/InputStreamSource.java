package com.mfilipo.symantec.spe.engine.source;

import com.symantec.scanengine.api.ScanException;
import com.symantec.scanengine.api.StreamScanRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

/**
 * Created by filipowm on 2016-03-03.
 */
public class InputStreamSource implements Source {
    private static final Logger LOG = LoggerFactory.getLogger(InputStreamSource.class);

    private static final int BUFFER_SIZE = 4096;

    private final InputStream inputStream;

    public InputStreamSource(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    @Override
    public void write(StreamScanRequest ssr) throws IOException, ScanException {
        int len;
        byte[] buffer = new byte[BUFFER_SIZE];
        while ((len = inputStream.read(buffer)) != -1) {
            ssr.send(buffer, 0, len);
        }
    }

    @Override
    public void cleanup() throws IOException {
        inputStream.close();
    }

    @Override
    public long length() {
        try {
            return inputStream.available();
        } catch (IOException e) {
            LOG.error("Error while getting inputStream size", e);
            return 0;
        }
    }

    @Override
    public boolean exists() {
        return inputStream != null && length() > 0;
    }

    @Override
    public String toString() {
        return UUID.randomUUID().toString();
    }
}
