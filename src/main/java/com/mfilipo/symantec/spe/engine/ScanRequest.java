package com.mfilipo.symantec.spe.engine;

import com.google.common.base.MoreObjects;
import com.mfilipo.symantec.spe.engine.source.ByteArraySource;
import com.mfilipo.symantec.spe.engine.source.FileSource;
import com.mfilipo.symantec.spe.engine.source.InputStreamSource;
import com.mfilipo.symantec.spe.engine.source.Source;
import com.mfilipo.symantec.spe.utils.Validateable;
import org.apache.commons.io.output.CountingOutputStream;
import org.apache.commons.io.output.NullOutputStream;
import org.springframework.util.Assert;

import java.io.*;

/**
 * Created by filipowm on 2016-03-01.
 */
public final class ScanRequest implements Validateable {

    private boolean cleanupAfterScan;
    private Source source;
    private CountingOutputStream output;

    private ScanRequest(Source source, OutputStream output, boolean cleanupAfterScan) {
        this.source = source;
        this.output = new CountingOutputStream(output);
        this.cleanupAfterScan = cleanupAfterScan;
    }

    public boolean isCleanupAfterScan() {
        return cleanupAfterScan;
    }

    public Source getSource() {
        return source;
    }

    public long getOutpusSize() {
        return output.getByteCount();
    }

    public OutputStream getOutput() {
        return output;
    }

    public static ScanRequestBuilder builder() {
        return new ScanRequestBuilder();
    }

    @Override
    public void validate() {
        Assert.notNull(source);
    }

    static class ScanRequestBuilder {

        private boolean cleanupAfterScan = false;
        private Source source;
        private OutputStream output;

        private ScanRequestBuilder() { }

        public ScanRequestBuilder from(String path) throws FileNotFoundException {
            this.source = new FileSource(path);
            return this;
        }

        public ScanRequestBuilder from(File file) throws FileNotFoundException {
            this.source = new FileSource(file);
            return this;
        }

        public ScanRequestBuilder from(InputStream inputStream) throws IOException {
            this.source = new InputStreamSource(inputStream);
            return this;
        }

        public ScanRequestBuilder from(byte[] bytes) throws IOException {
            this.source = new ByteArraySource(bytes);
            return this;
        }

        public ScanRequestBuilder to(String path) throws FileNotFoundException {
            return to(new FileOutputStream(path));
        }

        public ScanRequestBuilder to(File file) throws FileNotFoundException {
            return to(new FileOutputStream(file));
        }

        public ScanRequestBuilder to(OutputStream outputStream) {
            this.output = outputStream;
            return this;
        }

        public ScanRequestBuilder removeAfterScan(boolean removeAfterScan) {
            this.cleanupAfterScan = removeAfterScan;
            return this;
        }

        public ScanRequest build() {
            if (output == null) {
                output = new NullOutputStream();
            }
            return new ScanRequest(source, output, cleanupAfterScan);
        }

    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("inputFile", source.toString())
                .add("inputSize", source.length())
                .add("outputSize", getOutpusSize())
                .add("cleanupAfterScan", cleanupAfterScan)
                .omitNullValues()
                .toString();
    }

}
