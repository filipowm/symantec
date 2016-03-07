package com.mfilipo.symantec.spe.engine.source;

import com.symantec.scanengine.api.ScanException;
import com.symantec.scanengine.api.StreamScanRequest;

import java.io.IOException;

/**
 * Created by filipowm on 2016-03-03.
 */
public interface Source {

    void write(StreamScanRequest ssr) throws IOException, ScanException;
    void cleanup() throws IOException;
    long length();
    boolean exists();

}
