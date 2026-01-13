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

class HttpCensorshipProbe(private val config: CensorScannerConfig) : CensorProbe(CensorProbeType.HTTP) {
    private var blocksPath = false
    private var blocksHost = false
    private var blocksResponse = false

    init {
        register(
            CensorAnalyzedProperty.BLOCKS_PATH,
            CensorAnalyzedProperty.BLOCKS_HOST,
            CensorAnalyzedProperty.BLOCKS_RESPONSE
        )
    }

    override fun getRequirements(): Requirement<CensorReport> {
        return FulfilledRequirement()
    }

    override fun adjustConfig(censorReport: CensorReport) {
    }

    /**
     * Scans for SNI-based censorship
     */
    override fun executeTest() {
        runBlocking(Dispatchers.IO) {
            // send HTTP-based test vectors for path- and Host-based censorship
            val pathData = "GET ${config.path} HTTP/1.1\r\n" +
                    "Host: harmless.com\r\n" +
                    "\r\n"
            val tcpDataConnectionPath = prepareTcpDataConnection(pathData.toByteArray(Charsets.ISO_8859_1))
            try {
                tcpDataConnectionPath.connect()
                ConnectionReturn.WORKING
            } catch (e: NotConnectableException) {
                e.reason
                println(e.reason)
                blocksPath = true
            }

            val hostData = "GET / HTTP/1.1\r\n" +
                    "Host: ${config.hostname}\r\n" +
                    "\r\n"
            val tcpDataConnectionHost = prepareTcpDataConnection(hostData.toByteArray(Charsets.ISO_8859_1))
            try {
                tcpDataConnectionHost.connect()
                ConnectionReturn.WORKING
            } catch (e: NotConnectableException) {
                e.reason
                println(e.reason)
                blocksHost = true
            }

            val responseData = "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/html; charset=ISO-8859-1\r\n" +
                    "Content-Length: ${1 + config.hostname.length + config.path.length}\r\n" +
                    "\r\n" +
                    "${config.hostname} ${config.path}"// Body with keywords
            val tcpDataConnectionResponse = prepareTcpDataConnection(responseData.toByteArray(Charsets.ISO_8859_1))
            try {
                tcpDataConnectionResponse.connect()
                ConnectionReturn.WORKING
            } catch (e: NotConnectableException) {
                e.reason
                println(e.reason)
                blocksResponse = true
            }
        }
    }

    private fun prepareTcpDataConnection(data: ByteArray): TcpDataConnection {
        return TcpDataConnection(
            config.getIpAddress(),
            if (config.echo) 7 else 80,
            config.timeout,
            echo = config.echo,
            pcapCapturer = PcapCapturer(bpfExpression = "tcp or udp"),
            data = data
        )
    }

    override fun mergeData(censorReport: CensorReport) {
        put(CensorAnalyzedProperty.BLOCKS_PATH, TestResults.of(blocksPath))
        put(CensorAnalyzedProperty.BLOCKS_HOST, TestResults.of(blocksHost))
        put(CensorAnalyzedProperty.BLOCKS_RESPONSE, TestResults.of(blocksResponse))
    }
}