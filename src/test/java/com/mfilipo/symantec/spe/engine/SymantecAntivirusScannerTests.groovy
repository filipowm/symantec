package com.mfilipo.symantec.spe.engine

import com.mfilipo.symantec.spe.engine.config.AntivirusConfig
import com.mfilipo.symantec.spe.event.AntivirusListener
import com.mfilipo.symantec.spe.event.ScanFailureEvent
import com.mfilipo.symantec.spe.event.ScanSuccessEvent
import com.mfilipo.symantec.spe.exception.ScanFailedException
import com.symantec.scanengine.api.ErrorCode
import com.symantec.scanengine.api.Result
import com.symantec.scanengine.api.ScanException
import com.symantec.scanengine.api.StreamScanRequest
import spock.lang.Specification

/**
 * Created by filipowm on 2016-03-02.
 */

class SymantecAntivirusScannerTests extends Specification {

    private static mockConfig() {
        new AntivirusConfig('test', 1)
    }

    private static mockScanner() {
        new SymantecAntivirusScanner(mockConfig())
    }

    private static mockScanRequest() {
        mockScanRequest('test')
    }

    private static mockScanRequest(String from) {
        ScanRequest.builder()
                .from(from.bytes)
                .removeAfterScan(true)
                .build()
    }

    private static mockScanRequest(String from, String to) {
        ScanRequest.builder()
                .from(from.bytes)
                .to(to)
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

    void 'scan failed with exception'() {
        given:
        def scanner = mockScanner()
        def eventDispatcher = Mock(SymantecAntivirusScanner.EventDispatcher, constructorArgs: [[]]) {
            dispatch(_) >> "ok"
        }
        scanner.@eventDispatcher = eventDispatcher
        def scanRequest = mockScanRequest()

        StreamScanRequest.metaClass.scanFile = { throw new ScanException('test', ErrorCode.ERROR_FILE_CREATION)}

        when:
        scanner.scan(scanRequest)

        then:
        thrown ScanFailedException
        1 * eventDispatcher.dispatch(_ as ScanFailureEvent)
        ! scanRequest.getSource().exists()
    }

    void 'scan executed with result'() {
        given:
        def scanner = mockScanner()
        def eventDispatcher = Mock(SymantecAntivirusScanner.EventDispatcher, constructorArgs: [[]]) {
            dispatch(_) >> "ok"
        }
        scanner.@eventDispatcher = eventDispatcher
        def scanRequest = mockScanRequest()

        StreamScanRequest.metaClass.scanFile = {
            return new Result()
        }

        when:
        Optional<Result> result = scanner.scan(scanRequest)

        then:
        noExceptionThrown()
        1 * eventDispatcher.dispatch(_ as ScanSuccessEvent)
        ! scanRequest.getSource().exists()
        result.present

    }

}
