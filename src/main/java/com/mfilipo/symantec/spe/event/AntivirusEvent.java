package com.mfilipo.symantec.spe.event;

import org.springframework.context.ApplicationEvent;

/**
 * Created by filipowm on 2016-02-25.
 */
public abstract class AntivirusEvent extends ApplicationEvent  {
    /**
     * Create a new ApplicationEvent.
     *
     * @param source the object on which the event initially occurred (never {@code null})
     */
    public AntivirusEvent(Object source) {
        super(source);
    }
}
