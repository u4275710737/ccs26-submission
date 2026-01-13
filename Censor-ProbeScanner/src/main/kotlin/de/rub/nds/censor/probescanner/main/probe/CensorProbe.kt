package de.rub.nds.censor.probescanner.main.probe

import de.rub.nds.censor.probescanner.main.constants.CensorProbeType
import de.rub.nds.censor.probescanner.main.report.CensorReport
import de.rub.nds.scanner.core.probe.ScannerProbe
import de.rub.nds.tlsattacker.core.state.State

/**
 * Abstract super class for probes. Each probes analyses a distinct feature of censorship behavior.
 */
abstract class CensorProbe(private val probeType: CensorProbeType): ScannerProbe<CensorReport, State>(probeType) {

    override fun getType(): CensorProbeType {
        return probeType
    }
}