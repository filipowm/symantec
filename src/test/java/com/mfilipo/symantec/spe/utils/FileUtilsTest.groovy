package com.mfilipo.symantec.spe.utils

import org.apache.commons.io.IOUtils
import spock.lang.Shared
import spock.lang.Specification

/**
 * Created by filipowm on 2016-03-02.
 */

class FileUtilsTest extends Specification {

    @Shared
    private List<String> testStrings = ['aaaa', 'a1b2c3d4e5f6', '1234567890-=+_)(*&^%#@!', '~qwertyuiop[]asdfghjkl;\'\\zxcvbnm,./']

    void 'create empty temp file'() {
        given:
        File tmpFile = FileUtils.createTempFile()

        expect:
        tmpFile.name.endsWith('.tmp')
        tmpFile.length() == 0

        cleanup:
        tmpFile.delete()
    }

    void 'create temp file from input stream'() {
        given:
        InputStream stub = IOUtils.toInputStream(input)

        when:
        File tmpFile = FileUtils.toTempFile(stub);

        then:
        tmpFile.name.endsWith('.tmp')
        tmpFile.length() == input.length()

        cleanup:
        tmpFile.delete()

        where:
        input << testStrings
    }

    void 'create temp file from byte array'() {
        given:
        byte[] stub = input.bytes

        when:
        File tmpFile = FileUtils.toTempFile(stub);

        then:
        tmpFile.name.endsWith('.tmp')
        tmpFile.length() == input.length()

        cleanup:
        tmpFile.delete()

        where:
        input << testStrings
    }
}
