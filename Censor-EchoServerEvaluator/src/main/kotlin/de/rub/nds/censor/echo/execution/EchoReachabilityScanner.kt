package de.rub.nds.censor.echo.execution

import de.rub.nds.censor.core.connection.TcpDataConnection
import de.rub.nds.censor.core.connection.UdpDataConnection
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.data.ServerAddress
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.echo.config.EchoEvalConfig
import de.rub.nds.censor.echo.data.EchoServerResult
import de.rub.nds.censor.echo.main.runCommand
import kotlinx.coroutines.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
import me.tongfei.progressbar.ProgressBar
import org.apache.logging.log4j.kotlin.Logging
import java.io.File
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.system.measureTimeMillis

/**
 * Scanner that evaluates the reachability of Echo servers. Scan parameters are defined through the given config.
 * The PcapCapturer is used for analyzing the responses of servers.
 */
class EchoReachabilityScanner(
    val echoEvalConfig: EchoEvalConfig,
    val pcapCapturer: PcapCapturer,
    val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : Logging{

    @OptIn(ExperimentalStdlibApi::class)
    fun scanServer(server: ServerAddress): ConnectionReturn {
        if (echoEvalConfig.scanUdp) {
            UdpDataConnection(server.ip,
                server.port,
                echoEvalConfig.timeout,
                pcapCapturer = pcapCapturer,
                data = echoEvalConfig.echoTestData.hexToByteArray()).also { udpDataConnection ->
                return runBlocking {
                    try {
                        udpDataConnection.connect()
                        ConnectionReturn.WORKING
                    } catch (exception: NotConnectableException) {
                        exception.reason
                    }
                }
            }
        } else {
            TcpDataConnection(server.ip,
                server.port,
                echoEvalConfig.timeout,
                pcapCapturer = pcapCapturer,
                data = echoEvalConfig.echoTestData.hexToByteArray()).also { tcpEchoConnection ->
                return runBlocking {
                    try {
                        tcpEchoConnection.connect()
                        ConnectionReturn.WORKING
                    } catch (exception: NotConnectableException) {
                        exception.reason
                    }
                }
            }
        }
    }

    /**
     * Executes an Echo reachability scan by first executing a ZMap scan and then scanning the corresponding IPs.
     * The results are persisted into a JSON file and working results are returned.
     */
    @OptIn(ExperimentalSerializationApi::class)
    fun execute(inCludeHours: Boolean = false): List<EchoServerResult> {
        var formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
        if (inCludeHours) {
            formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH")
        }
        val startDate = LocalDateTime.now().format(formatter)
        val echoServerResultList = if (echoEvalConfig.echoIPs.isNotEmpty()){
            logger.info("List of Echo IPs provided in config, starting directly with evaluation without using ZMap")
            echoEvalConfig.echoIPs.map { ip -> EchoServerResult(Ipv4Address(ip)) }
        } else {
            if (!echoEvalConfig.skipZmap) {
                if (echoEvalConfig.scanUdp) {
                    logger.info("Running Internet-wide ZMap on UDP port 7...")
                } else {
                    logger.info("Running Internet-wide ZMap on TCP port 7...")
                }
                ZMapScanner(echoEvalConfig).execute().map { ip -> EchoServerResult(Ipv4Address(ip)) }
            } else {
                logger.info("Skipping ZMap...")
                val ipList = File(echoEvalConfig.zmapOutputFileIdentifier).useLines { it.toMutableList() }
                if (ipList.isNotEmpty() && ipList[0].contains("saddr")) {
                    ipList.removeAt(0)
                }
                ipList.map { ip -> EchoServerResult(Ipv4Address(ip)) }
            }
        }

        pcapCapturer.start()
        val reachabilityScanTime = measureTimeMillis {
            // enter the coroutine world here to execute each connection in parallel
            val progressBar = ProgressBar("Test Vectors", echoServerResultList.size.toLong())
            runBlocking {
                // evaluate each test vector in parallel
                val deferredResults = echoServerResultList.map{ echoServer ->
                    async(dispatcher) {
                        echoServer.apply { result =  scanServer(ServerAddress(echoServer.echoIP, 7, ""))}
                    }.also { it.invokeOnCompletion { progressBar.step() } }
                }
                // await completion of all test vectors
                deferredResults.toList().awaitAll()
                // finish progress bar, and persist results
                progressBar.stepTo(progressBar.max)
                progressBar.close()
                Json.encodeToStream(
                    echoServerResultList,
                    File("${echoEvalConfig.outputFileIdentifier}_${startDate}.json").outputStream()
                )
            }
        }
        logger.info("Reachability scan took ${reachabilityScanTime.toDouble() / 3600000} hours")

        val workingServers = echoServerResultList.filter { echoServerResult -> echoServerResult.result == ConnectionReturn.WORKING}

        if(!echoEvalConfig.skipNmap) {
            // perform nmap scan with sample size of working servers
            val sampleSize = (workingServers.size * echoEvalConfig.nmapSampleSize).toInt().coerceAtLeast(1) // Ensure at least 1 item
            val nmapSample = workingServers.shuffled().take(sampleSize)
            val inputFile = "${echoEvalConfig.nmapInputFileIdentifier}_$startDate.txt"
            File(inputFile).bufferedWriter().use { out ->
                nmapSample.forEach {
                    out.write("${it.echoIP}\n")
                }
            }
            val nmapScanTime = measureTimeMillis {
                val nmapCommand = "nmap -R -O --max-os-tries 3 -d -v -T4 -iL $inputFile -oN ${echoEvalConfig.nmapOutputFileIdentifier}_$startDate.txt"
                nmapCommand.runCommand()
            }
            logger.info("Nmap scan took ${nmapScanTime.toDouble() / 3600000} hours")
        }

        pcapCapturer.stop()
        return workingServers
    }
}