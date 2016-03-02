package com.mfilipo.symantec.spe.event;

import org.springframework.context.ApplicationEvent;

import java.io.File;

/**
 * Created by filipowm on 2016-02-25.
 */
public abstract class AntivirusEvent extends ApplicationEvent  {

    public AntivirusEvent(File source) {
        super(source);
    }

    public AntivirusEvent(String source) {
        super(source);
    }

    public String getSource() {
        if (source instanceof File) {
            return ((File) source).getName();
        }
        return source.toString();
    }

    public String getFile() {
        return getSource();
    }
}
