package com.mfilipo.symantec.spe.engine;

import com.google.common.io.Files;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
/**
 * Created by filipowm on 2016-03-01.
 */
public final class FileUtils {

    public static File toTempFile(InputStream stream) throws IOException {
        File temp = createTempFile();
        org.apache.commons.io.FileUtils.copyInputStreamToFile(stream, temp);
        return temp;
    }

    public static File toTempFile(byte[] bytes) throws IOException {
        File temp = createTempFile();
        Files.write(bytes, temp);
        return temp;
    }

    public static File createTempFile() throws IOException {
        return File.createTempFile(UUID.randomUUID().toString(), ".tmp");
    }
}
