package com.mfilipo.symantec.spe.engine;

import com.google.common.base.MoreObjects;
import com.mfilipo.symantec.spe.utils.FileUtils;
import org.apache.commons.io.output.CountingOutputStream;
import org.apache.commons.io.output.NullOutputStream;

import java.io.*;

/**
 * Created by filipowm on 2016-03-01.
 */
public final class ScanRequest {

    private boolean removeAfterScan;
    private File input;
    private CountingOutputStream output;

    private ScanRequest(File input, OutputStream output, boolean removeAfterScan) {
        this.input = input;
        this.output = new CountingOutputStream(output);
        this.removeAfterScan = removeAfterScan;
    }

    public boolean isRemoveAfterScan() {
        return removeAfterScan;
    }

    public File getInput() {
        return input;
    }

    public long getInputSize() {
        return input.length();
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

    static class ScanRequestBuilder {

        private boolean removeAfterScan = false;
        private boolean blockRemoveAfterScan = false;
        private File input;
        private OutputStream output;

        private ScanRequestBuilder() { }

        public ScanRequestBuilder from(String path) {
            return from(new File(path));
        }

        public ScanRequestBuilder from(File file) {
            this.input = file;
            return this;
        }

        public ScanRequestBuilder from(InputStream inputStream) throws IOException {
            if (! blockRemoveAfterScan) {
                removeAfterScan = true;
            }
            return from(FileUtils.toTempFile(inputStream));
        }

        public ScanRequestBuilder from(byte[] bytes) throws IOException {
            if (! blockRemoveAfterScan) {
                removeAfterScan = true;
            }
            return from(FileUtils.toTempFile(bytes));
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
            this.removeAfterScan = removeAfterScan;
            this.blockRemoveAfterScan = true;
            return this;
        }

        public ScanRequest build() {
            if (input == null) {
                throw new NullPointerException("input can't be null");
            }
            if (output == null) {
                output = new NullOutputStream();
            }
            return new ScanRequest(input, output, removeAfterScan);
        }

    }

    @Override
    public String toString() {
        CountingOutputStream cos = new CountingOutputStream(output);
        return MoreObjects.toStringHelper(this)
                .add("inputFile", input.getAbsolutePath())
                .add("inputSize", getInputSize())
                .add("outputSize", getOutpusSize())
                .add("removeAfterScan", removeAfterScan)
                .omitNullValues()
                .toString();
    }

}
