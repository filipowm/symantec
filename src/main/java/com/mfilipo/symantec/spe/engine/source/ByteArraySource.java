package com.mfilipo.symantec.spe.engine.source;

import com.symantec.scanengine.api.ScanException;
import com.symantec.scanengine.api.StreamScanRequest;

import java.io.IOException;
import java.util.UUID;

/**
 * Created by filipowm on 2016-03-03.
 */
public class ByteArraySource implements Source {

    private byte[] bytes;

    public ByteArraySource(byte[] bytes) {
        this.bytes = bytes;
    }

    @Override
    public void write(StreamScanRequest ssr) throws IOException, ScanException {
        ssr.send(bytes);
    }

    @Override
    public void cleanup() throws IOException {
        bytes = new byte[0];
    }

    @Override
    public long length() {
        return bytes.length;
    }

    @Override
    public boolean exists() {
        return bytes != null && bytes.length > 0;
    }

    @Override
    public String toString() {
        return UUID.randomUUID().toString();
    }
}
