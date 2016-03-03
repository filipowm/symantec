package com.mfilipo.symantec.spe.utils;

import org.springframework.util.Assert;

/**
 * Created by filipowm on 2016-03-03.
 */
public interface Validateable {

    void validate();

    static void validate(Validateable validateable) {
        Assert.notNull(validateable);
        validateable.validate();
    }
}
