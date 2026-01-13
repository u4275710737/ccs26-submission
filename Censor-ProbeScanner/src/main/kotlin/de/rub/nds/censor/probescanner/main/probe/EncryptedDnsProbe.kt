package de.rub.nds.censor.probescanner.main.probe

import de.rub.nds.censor.probescanner.main.constants.CensorAnalyzedProperty
import de.rub.nds.censor.probescanner.main.constants.CensorProbeType
import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.Ip
import de.rub.nds.censor.core.constants.Port
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.probescanner.main.config.CensorScannerConfig
import de.rub.nds.scanner.core.probe.requirements.FulfilledRequirement
import de.rub.nds.scanner.core.probe.requirements.Requirement
import de.rub.nds.scanner.core.probe.result.TestResults
import de.rub.nds.censor.probescanner.main.report.CensorReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking

/**
 * Evaluates DNS censorship happening on the machine.
 */
class EncryptedDnsProbe(private val config: CensorScannerConfig): CensorProbe(CensorProbeType.DNS) {

    private var blocksDoT = false
    private var blocksDoH = false

    private val blockedDoTServers = mutableListOf<Ip>()
    private val blockedDoHServers = mutableListOf<Ip>()

    init {
        register(
            CensorAnalyzedProperty.BLOCKS_DOH,
            CensorAnalyzedProperty.BLOCKS_DOT,
            CensorAnalyzedProperty.BLOCKED_DOT_SERVERS,
            CensorAnalyzedProperty.BLOCKED_DOH_SERVERS
        )
    }

    override fun getRequirements(): Requirement<CensorReport> {
        return FulfilledRequirement()
    }

    override fun adjustConfig(censorReport: CensorReport) {
    }

    /**
     * Scans each DNS server for their reachability on Port 53 DNS, Port 443 DoH, and Port 853 DoT
     */
    override fun executeTest() {
        val relevantServers = getRelevantServers()
        relevantServers.forEach {
            runBlocking(Dispatchers.IO) {
                val blocksDoT = async { !scanDoT(it).working() }
                val blocksDoH = async { !scanDoH(it).working() }
                // TODO: refine when connection analysis is done
                this@EncryptedDnsProbe.blocksDoT = this@EncryptedDnsProbe.blocksDoT || blocksDoT.await()
                this@EncryptedDnsProbe.blocksDoH = this@EncryptedDnsProbe.blocksDoH || blocksDoH.await()

                if (blocksDoT.await()) {
                    blockedDoTServers.add(it)
                }
                if (blocksDoH.await()) {
                    blockedDoHServers.add(it)
                }
            }
        }
    }

    override fun mergeData(censorReport: CensorReport) {
        put(CensorAnalyzedProperty.BLOCKS_DOT, TestResults.of(blocksDoT))
        put(CensorAnalyzedProperty.BLOCKS_DOH, TestResults.of(blocksDoH))
        put(CensorAnalyzedProperty.BLOCKED_DOT_SERVERS, blockedDoTServers)
        put(CensorAnalyzedProperty.BLOCKED_DOH_SERVERS, blockedDoHServers)
    }

    /**
     * Returns relevant DNS servers to scan.
     * TODO: provide this in config?
     */
    private fun getRelevantServers(): List<Ip> {
        return listOf(
            Ip.GOOGLE_DNS_1,
            Ip.GOOGLE_DNS_2,
            Ip.CLOUDFLARE_DNS_1,
            Ip.CLOUDFLARE_DNS_2,
            Ip.QUAD9_1,
            Ip.QUAD9_2
        )
    }

    /**
     * Whether a server responds to DoT on port 853
     */
    private suspend fun scanDoT(server: Ip): ConnectionReturn {
        return scanServer(server = server, port = Port.DNS_OVER_TLS)
    }

    /**
     * Whether a server responds to DoH on port 443
     */
    private suspend fun scanDoH(server: Ip): ConnectionReturn {
        return scanServer(server = server, port = Port.DNS_OVER_HTTPS)
    }

    private suspend fun scanServer(server: Ip, port: Port): ConnectionReturn {
        // simply open a TLS connection to the server and see whether the handshake executes
        val tlsConnection = TlsConnection(server.ipAddress, port.portNumber, config.timeout, CensorScanType.DIRECT)
        return try {
            tlsConnection.connect()
            ConnectionReturn.WORKING
        } catch (e: NotConnectableException) {
            e.reason
        }
    }
}