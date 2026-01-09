package de.rub.nds.censor.probescanner.main.probe

import de.rub.nds.censor.core.connection.TcpDataConnection
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.probescanner.main.config.CensorScannerConfig
import de.rub.nds.censor.probescanner.main.constants.CensorAnalyzedProperty
import de.rub.nds.censor.probescanner.main.constants.CensorProbeType
import de.rub.nds.censor.probescanner.main.report.CensorReport
import de.rub.nds.scanner.core.probe.requirements.FulfilledRequirement
import de.rub.nds.scanner.core.probe.requirements.Requirement
import de.rub.nds.scanner.core.probe.result.TestResults
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

class TcpInTcpCensorshipProbe(private val config: CensorScannerConfig) : CensorProbe(CensorProbeType.TCP) {
    private var blocksTCP = false

    init {
        register(
            CensorAnalyzedProperty.BLOCKS_TCP
        )
    }

    override fun getRequirements(): Requirement<CensorReport> {
        return FulfilledRequirement()
    }

    override fun adjustConfig(censorReport: CensorReport) {
    }

    /**
     * Scans for IP-based censorship
     */
    @OptIn(ExperimentalStdlibApi::class)
    override fun executeTest() {
        runBlocking(Dispatchers.IO) {
            // send TCP-based censorship test vectors
            //val tcpConnectionData =
            //    prepareTcpDataConnection("02010a25498a82010a25498a08004500003c201a4000310664487a72a6e7${config.getCensoredIpAsHex()}a66101bb05feae2c00000000a002faf014ec0000020405b40402080a3cc3d9be0000000001030307".hexToByteArray())
            val tcpConnectionData = prepareTcpDataConnection("MAIL FROM: test@mail.de\r\n".toByteArray(Charsets.ISO_8859_1))
            try {
                tcpConnectionData.connect()
                ConnectionReturn.WORKING
            } catch (e: NotConnectableException) {
                e.reason
                println(e.reason)
                blocksTCP = true
            }
        }
    }

    private fun prepareTcpDataConnection(data: ByteArray): TcpDataConnection {
        return TcpDataConnection(
            config.getIpAddress(),
            if (config.echo) 7 else 25,
            config.timeout,
            echo = config.echo,
            pcapCapturer = PcapCapturer(bpfExpression = "tcp or udp"),
            data = data
        )
    }

    override fun mergeData(censorReport: CensorReport) {
        put(CensorAnalyzedProperty.BLOCKS_TCP, TestResults.of(blocksTCP))
    }
}