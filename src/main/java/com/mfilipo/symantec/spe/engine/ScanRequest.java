package com.mfilipo.symantec.spe.engine;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by filipowm on 2016-03-01.
 */
public class ScanRequest {

    private boolean removeAfterScan;
    private File input;
    private OutputStream output;


    public static ScanRequest from(String path) {

    }
    public static ScanRequest from(File file) {

    }
    public static ScanRequest from(InputStream inputStream) {

    }
    public static ScanRequest from(byte[] bytes) {

    }

    public static ScanRequestBuilder builder() {
        return new ScanRequestBuilder();
    }

    static class ScanRequestBuilder {

        private final boolean removeAfterScan;

        public ScanRequestBuilder(boolean removeAfterScan) {
            this.removeAfterScan = removeAfterScan;
        }

        public ScanRequestBuilder() {
            this(false);
        }

        public ScanRequestFrom from(String path) {

        }

        public ScanRequestFrom from(File file) {

        }

        public ScanRequestFrom from(InputStream inputStream) {

        }

        public ScanRequestFrom from(byte[] bytes) {

        }

    }
    class ScanRequestFrom {

        private final boolean removeAfterScan;
        private final File from;

        public ScanRequestTo to(String path) {
            return ScanRequestTo
        }

        public ScanRequestTo to(File file) {

        }

        public ScanRequestTo to(OutputStream outputStream) {

        }

        ScanRequestFrom (File file, boolean removeAfterScan) {
            this.from = file;
            this.removeAfterScan = removeAfterScan;
        }
    }

    class ScanRequestTo {

        private final boolean removeAfterScan;
        private final File from;

        ScanRequestFrom (File file, boolean removeAfterScan) {
            this.from = file;
            this.removeAfterScan = removeAfterScan;
        }

       public ScanRequest build() {

       }
    }



}
