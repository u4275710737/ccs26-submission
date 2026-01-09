package de.rub.nds.censor.echo.execution

import de.rub.nds.censor.echo.config.EchoEvalConfig
import de.rub.nds.censor.echo.main.runCommand
import org.apache.logging.log4j.kotlin.Logging
import java.io.File

/**
 * Class that is used for performing scans with ZMap. The command is defined through given config parameters.
 */
class ZMapScanner(
    private val echoEvalConfig: EchoEvalConfig
): Logging{
    /**
     * Executes the ZMap scan and returns a list of identified TCP Echo servers.
     */
    fun execute() : List<String> {
        try {
            // reset ZMap file
            File(echoEvalConfig.zmapOutputFileIdentifier).delete()
            File(echoEvalConfig.zmapOutputFileIdentifier).createNewFile()

            // run command and wait for it to finish, then return values
            var  command = "zmap -p 7 -b ${echoEvalConfig.zmapDenylist} -o ${echoEvalConfig.zmapOutputFileIdentifier} -r ${echoEvalConfig.zmapPPS}"
            if (echoEvalConfig.zmapInterface != "") {
                command += " -i ${echoEvalConfig.zmapInterface}"
            }
            if (echoEvalConfig.zmapThreads != 0) {
                command += " --sender-threads=${echoEvalConfig.zmapThreads}"
            }
            if (echoEvalConfig.zmapBandwith != "") {
                command += " -B ${echoEvalConfig.zmapBandwith}"
            }
            if (echoEvalConfig.scanUdp) {
                command += " -M udp --probe-args=text:testdata -f saddr --output-filter=\"success=1&&repeat=0\""
            }
            logger.info("Executing zmap command: $command")
            command.runCommand()

            val ipList = File(echoEvalConfig.zmapOutputFileIdentifier).useLines { it.toMutableList() }
            if (ipList.isNotEmpty() && ipList[0].contains("saddr")) {
                ipList.removeAt(0)
            }
            return ipList.toList()
        } catch (e: Exception) {
            logger.error("ZMap threw an exception. Try putting a valid denylist under ${echoEvalConfig.zmapDenylist}  or provide an explicit interface in the config")
            throw RuntimeException(e)
        }
    }
}