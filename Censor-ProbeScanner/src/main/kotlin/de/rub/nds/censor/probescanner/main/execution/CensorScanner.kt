package de.rub.nds.censor.probescanner.main.execution

import de.rub.nds.censor.probescanner.main.config.CensorScannerConfig
import de.rub.nds.censor.probescanner.main.probe.*
import de.rub.nds.censor.probescanner.main.report.CensorReport
import de.rub.nds.scanner.core.afterprobe.AfterProbe
import de.rub.nds.scanner.core.execution.Scanner
import de.rub.nds.scanner.core.passive.StatsWriter
import de.rub.nds.tlsattacker.core.state.State

/**
 *
 */
class CensorScanner(private val config: CensorScannerConfig): Scanner<CensorReport, CensorProbe, AfterProbe<CensorReport>, State>(config.executorConfig) {

    override fun close() { }

    /**
     * Adds all probes to be executed
     */
    override fun fillProbeLists() {
        //registerProbeForExecution(EncryptedDnsProbe(config)) //TODO: enable after testing
        registerProbeForExecution(TlsCensorshipProbe(config))
        registerProbeForExecution(HttpCensorshipProbe(config))
        registerProbeForExecution(TcpInTcpCensorshipProbe(config))
        registerProbeForExecution(DnsCensorshipProbe(config))
        registerProbeForExecution(QuicCensorshipProbe(config))
    }

    override fun getDefaultProbeWriter(): StatsWriter<State> {
        return StatsWriter()
    }

    override fun getEmptyReport(): CensorReport {
        return CensorReport()
    }

    override fun checkScanPrerequisites(censorReport: CensorReport): Boolean {
        return true
    }
}