package com.mfilipo.symantec.spe.engine

import com.mfilipo.symantec.spe.engine.config.AntivirusConfig
import spock.lang.Specification
import spock.lang.Unroll


/**
 * Created by filipowm on 2016-03-03.
 */
class AntivirusConfigTest extends Specification {

    @Unroll
    void 'config validation failed due to wrong value of #field = #value' () {
        given:
        AntivirusConfig config = new AntivirusConfig('test', 1)
        config.@"$field" = value

        when:
        config.validate()

        then:
        thrown IllegalArgumentException

        where:
        field | value
        'host' | null
        'port' | -1
        'port' | 0
        'policy' | null
        'failRetryTime' | -1
        'readWriteTime' | -1
    }
}