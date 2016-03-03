package com.mfilipo.symantec.spe.event;

import org.springframework.context.ApplicationListener;

/**
 * Created by filipowm on 2016-02-25.
 */
public interface AntivirusListener<T extends AntivirusEvent> extends ApplicationListener<T> {
}
