package com.mfilipo.symantec.spe.event;

import com.mfilipo.symantec.spe.engine.ScanRequest;
import org.springframework.context.ApplicationEvent;

/**
 * Created by filipowm on 2016-02-25.
 */
public abstract class AntivirusEvent extends ApplicationEvent  {

    public AntivirusEvent(ScanRequest source) {
        super(source);
    }

    public ScanRequest getSource() {
        return (ScanRequest) source;
    }

    public ScanRequest getScanRequest() {
        return getSource();
    }
}
