package com.mfilipo.symantec.spe.engine;

import org.apache.commons.io.output.NullOutputStream;

import java.io.*;

/**
 * Created by filipowm on 2016-03-01.
 */
public class ScanRequest {

    private boolean removeAfterScan;
    private File input;
    private OutputStream output;

    private ScanRequest(File input, OutputStream output, boolean removeAfterScan) {
        this.input = input;
        this.output = output;
        this.removeAfterScan = removeAfterScan;
    }

    public boolean isRemoveAfterScan() {
        return removeAfterScan;
    }

    public File getInput() {
        return input;
    }

    public OutputStream getOutput() {
        return output;
    }

    public static ScanRequestBuilder builder() {
        return new ScanRequestBuilder();
    }

    static class ScanRequestBuilder {

        private boolean removeAfterScan = false;
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
            removeAfterScan = true;
            return from(FileUtils.toTempFile(inputStream));
        }

        public ScanRequestBuilder from(byte[] bytes) throws IOException {
            removeAfterScan = true;
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



}
