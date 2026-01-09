package de.rub.nds.censor.echo.main

import com.beust.jcommander.JCommander
import com.beust.jcommander.ParameterException
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.echo.config.EchoEvalConfig
import de.rub.nds.censor.echo.execution.EchoReachabilityScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.IO
import org.apache.logging.log4j.LogManager
import java.lang.Thread.sleep
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*

@OptIn(ExperimentalCoroutinesApi::class)
fun main(args: Array<String>) {
    val config = EchoEvalConfig()
    val jCommander = JCommander(config)
    try {
        jCommander.parse(*args)
        config.apply()
    } catch (e: ParameterException) {
        LogManager.getLogger().error(e)
        jCommander.usage()
        return
    }

    // wait for next day to start
    val initialFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
    val initialDate = LocalDateTime.now().format(initialFormatter)
    while (!config.skipInitialWait) {
        if (initialDate == LocalDateTime.now().format(initialFormatter)) {
            LogManager.getLogger().info("Waiting 30 more seconds for the day to start!")
            sleep(30000)
        }
        else {
            break
        }
    }

    // executes a scan at the rate of the given period
    val initialZmapValue = config.skipZmap
    val initialNmapValue = config.skipNmap
    var firstExecution = true
    Timer().scheduleAtFixedRate(object : TimerTask() {
        override fun run() {
            if (!firstExecution) {
                // reset config values for further repeating executions
                config.skipZmap = initialZmapValue
                config.echoIPs = emptyList()
                config.skipNmap = initialNmapValue
            }
            firstExecution = false
            val scanner = EchoReachabilityScanner(
                echoEvalConfig = config,
                dispatcher = Dispatchers.IO.limitedParallelism(config.threads),
                pcapCapturer = PcapCapturer(interfaceName = config.networkInterface, bpfExpression = "tcp or udp"),
            )
            val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
            val startDate = LocalDateTime.now().format(formatter)
            val workingResults = scanner.execute()

            config.skipZmap = true // disable ZMap and NMap for hourly scan
            config.skipNmap = true
            config.echoIPs = workingResults.map { echoServerResult -> echoServerResult.echoIP.address} // select working

            // at the given repetitionPeriod, rescan working servers from first scan until the day ends
            Timer().scheduleAtFixedRate(object : TimerTask() {
                override fun run() {
                    if (startDate != LocalDateTime.now().format(formatter)) {
                        LogManager.getLogger().info("Cancelled repeating task because the next day has been reached!")
                        cancel() // stop the task if next day
                    }
                    else {
                        val hourlyScanner = EchoReachabilityScanner(
                            echoEvalConfig = config,
                            dispatcher = Dispatchers.IO.limitedParallelism(config.threads),
                            pcapCapturer = PcapCapturer(interfaceName = config.networkInterface, bpfExpression = "tcp or udp"),
                        )
                        hourlyScanner.execute(inCludeHours = true)
                    }
                }
            }, 0, config.repetitionPeriod)
        }
    },0, config.taskPeriod)
}

/**
 * Helper function for running commands.
 */
fun String.runCommand() {
    ProcessBuilder(*split(" ").toTypedArray())
        .redirectOutput(ProcessBuilder.Redirect.INHERIT)
        .redirectError(ProcessBuilder.Redirect.INHERIT)
        .start()
        .waitFor()
}