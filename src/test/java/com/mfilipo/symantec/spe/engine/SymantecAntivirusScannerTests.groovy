package com.mfilipo.symantec.spe.engine

import com.mfilipo.symantec.spe.engine.config.AntivirusConfig
import com.mfilipo.symantec.spe.event.AntivirusListener
import spock.lang.Specification

/**
 * Created by filipowm on 2016-03-02.
 */

class SymantecAntivirusScannerTests extends Specification {

    private static mockConfig() {
        new AntivirusConfig('test', 1)
    }

    private static mockScanRequest() {
        ScanRequest.builder()
                .from('test')
                .removeAfterScan(true)
                .build()
    }

    void 'scanner create failed due to missing AntivirusConfig' () {
        when:
        new SymantecAntivirusScanner(null)

        then:
        thrown IllegalArgumentException
    }

    void 'scanner initialized correctly without listeners' () {
        given:
        def config = mockConfig()

        when:
        def scanner = new SymantecAntivirusScanner(config)

        then:
        scanner != null
        scanner.@engine != null
        scanner.@eventDispatcher != null
        scanner.@eventDispatcher.@antivirusListeners.empty
        scanner.@engine.portNumber[0] == config.port
        scanner.@engine.ipAddress[0] == config.host
        scanner.@engine.failRetryTime == config.failRetryTime
        scanner.@engine.readWriteTime == config.readWriteTime
    }

    void 'scanner initialized correctly with listener' () {
        given:
        def config = mockConfig()
        def listener = { event -> null } as AntivirusListener

        when:
        def scanner = new SymantecAntivirusScanner(config, listener)

        then:
        scanner != null
        scanner.@engine != null
        scanner.@eventDispatcher != null
        scanner.@eventDispatcher.@antivirusListeners.size() == 1
    }

    void 'no scan result due to disabled scanner'() {
        given:
        def config = mockConfig()
        config.enabled = false
        def scanner = new SymantecAntivirusScanner(config)
        def scanRequest = mockScanRequest()

        when:
        def result = scanner.scan(scanRequest)

        then:
        ! result.present
        noExceptionThrown()
    }

}
