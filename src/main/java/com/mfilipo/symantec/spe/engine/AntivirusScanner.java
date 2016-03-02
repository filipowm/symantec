package com.mfilipo.symantec.spe.engine;

import com.google.common.base.Optional;
import com.mfilipo.symantec.spe.engine.config.AntivirusConfig;
import com.symantec.scanengine.api.Result;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by filipowm on 2016-02-25.
 */
@Component
public interface AntivirusScanner {

    AntivirusConfig getAntivirusConfig();

    Optional<Result> scan(File file) throws IOException;
    Optional<Result> scan(File file, OutputStream saveStream) throws IOException;
    Optional<Result> scan(File file, File saveFile) throws IOException;
    Optional<Result> scan(File file, String savePath) throws IOException;
    Optional<Result> scan(String path) throws IOException;
    Optional<Result> scan(String path, OutputStream saveStream) throws IOException;
    Optional<Result> scan(String path, File saveFile) throws IOException;
    Optional<Result> scan(String path, String savePath) throws IOException;
    Optional<Result> scan(InputStream stream);
    Optional<Result> scan(InputStream stream, OutputStream saveStream);
    Optional<Result> scan(InputStream stream, File saveFile);
    Optional<Result> scan(InputStream stream, String savePath);
    Optional<Result> scan(byte[] bytes);
    Optional<Result> scan(byte[] bytes, OutputStream saveStream);
    Optional<Result> scan(byte[] bytes, File saveFile);
    Optional<Result> scan(byte[] bytes, String savePath);

}
