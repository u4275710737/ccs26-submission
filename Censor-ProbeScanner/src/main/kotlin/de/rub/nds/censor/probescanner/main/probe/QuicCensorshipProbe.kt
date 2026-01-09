package de.rub.nds.censor.probescanner.main.probe

import de.rub.nds.censor.core.connection.UdpDataConnection
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
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.connection.OutboundConnection
import de.rub.nds.tlsattacker.core.constants.SniType
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair
import de.rub.nds.tlsattacker.core.quic.crypto.QuicEncryptor
import de.rub.nds.tlsattacker.core.quic.frame.CryptoFrame
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket
import de.rub.nds.tlsattacker.core.state.Context
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.core.state.quic.QuicContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.charset.StandardCharsets
import java.util.*

class QuicCensorshipProbe(private val censorScannerConfig: CensorScannerConfig) : CensorProbe(CensorProbeType.QUIC) {
    private var blocksQuic = false

    init {
        register(
            CensorAnalyzedProperty.BLOCKS_QUIC
        )
    }

    override fun getRequirements(): Requirement<CensorReport> {
        return FulfilledRequirement()
    }

    override fun adjustConfig(censorReport: CensorReport) {
    }

    /**
     * Scans for QUIC-based censorship
     */
    override fun executeTest() {
        val config = Config()
        config.isAddServerNameIndicationExtension = true
        config.defaultSniHostnames = LinkedList(
            listOf(
                ServerNamePair(SniType.HOST_NAME.value,
                    censorScannerConfig.hostname.toByteArray(StandardCharsets.US_ASCII)
                )
            )
        )

        val state = State(config)
        val context = Context(state, OutboundConnection())
        context.quicContext = QuicContext(context)

        val msg = ClientHelloMessage(config)
        msg.getPreparator(context).prepare()
        val cryptData = msg.getSerializer(context).serialize()

        val frame = CryptoFrame()
        frame.cryptoDataConfig = cryptData
        frame.lengthConfig = cryptData.size.toLong()
        frame.getPreparator(context).prepare()

        val packet = InitialPacket(frame.getSerializer(context).serialize())
        packet.getPreparator(context).prepare()
        val encryptor = QuicEncryptor(context.quicContext)
        encryptor.encryptInitialPacket(packet)
        packet.updateFlagsWithEncodedPacketNumber()
        encryptor.addHeaderProtectionInitial(packet)
        val result = packet.getSerializer(context).serialize()

        runBlocking(Dispatchers.IO) {
            val quicData = prepareUdpDataConnection(result)
            try {
                quicData.connect()
                ConnectionReturn.WORKING
            } catch (e: NotConnectableException) {
                e.reason
                println(e.reason)
                blocksQuic = true
            }
        }
    }

    private fun prepareUdpDataConnection(data: ByteArray): UdpDataConnection {
        return UdpDataConnection(
            censorScannerConfig.getIpAddress(),
            if (censorScannerConfig.echo) 7 else 443,
            censorScannerConfig.timeout,
            echo = censorScannerConfig.echo,
            pcapCapturer = PcapCapturer(bpfExpression = "tcp or udp"),
            data = data,
            clientPort = if (censorScannerConfig.mimicClientPort) 443 else -1
        )
    }

    override fun mergeData(censorReport: CensorReport) {
        put(CensorAnalyzedProperty.BLOCKS_QUIC, TestResults.of(blocksQuic))
    }
}