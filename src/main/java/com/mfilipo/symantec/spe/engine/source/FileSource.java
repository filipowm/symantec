package com.mfilipo.symantec.spe.engine.source;

import com.symantec.scanengine.api.ScanException;
import com.symantec.scanengine.api.StreamScanRequest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Created by filipowm on 2016-03-03.
 */
public class FileSource implements Source {

    private final File file;
    private final InputStreamSource inputStreamSource;

    public FileSource(File file) throws FileNotFoundException {
        this.file = file;
        this.inputStreamSource = new InputStreamSource(new FileInputStream(file));
    }

    public FileSource(String path) throws FileNotFoundException {
        this(new File(path));
    }

    @Override
    public void write(StreamScanRequest ssr) throws ScanException, IOException {
        inputStreamSource.write(ssr);
    }

    @Override
    public void cleanup() throws IOException {
        inputStreamSource.cleanup();
        file.delete();
    }

    @Override
    public long length() {
        return file.length();
    }

    @Override
    public boolean exists() {
        return file.exists();
    }

    @Override
    public String toString() {
        return file.getName();
    }
}
