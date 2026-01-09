package de.rub.nds.censor.echo.config

import com.beust.jcommander.Parameter
import com.beust.jcommander.ParametersDelegate
import de.rub.nds.censor.core.config.Delegate
import de.rub.nds.censor.core.config.GeneralDelegate
import kotlinx.serialization.Transient

/**
 * Config that is used for the echo evaluation scanner. See parameter explanations below.
 */
class EchoEvalConfig: Delegate {

    @Parameter(
        names = ["-timeout"],
        required = false,
        description = "The timeout used for the scans in ms (default 5000)"
    )
    var timeout = 5000

    @Parameter(
        names = ["-keyLogFile"],
        required = false,
        description = "Location of the file key material will be saved to"
    )
    var keyLogFile = ""

    @Parameter(
        names = ["-outputFileIdentifier"],
        required = false,
        description = "Identifier that is used to store the Echo server evaluation result. During the evaluation, this will be appended with the current date."
    )
    var outputFileIdentifier = "echo_results"

    @Parameter(
        names = ["-interface"],
        required = false,
        description = "Network Interface to capture traffic on"
    )
    var networkInterface = "any"

    @Parameter(
        names = ["-threads"],
        required = false,
        description = "How many threads to use in parallelized connections"
    )
    var threads = 100

    @Parameter(
        names = ["-echoIPs"],
        required = false,
        description = "The IPs of the echo server to test"
    )
    var echoIPs : List<String> = emptyList()

    @Parameter(
        names = ["-zmapInterface"],
        required = false,
        description = "The interface that ZMap should use. Needs to be specified if ZMap finds conflicting default behavior on your system."
    )
    var zmapInterface = ""

    @Parameter(
        names = ["-zmapOutputFileIdentifier"],
        required = false,
        description = "Identifier for the file that the zmap output will be piped in."
    )
    var zmapOutputFileIdentifier = "zmap_output.txt"

    @Parameter(
        names = ["-zmapDenylist"],
        required = false,
        description = "Denyllist used by ZMap."
    )
    var zmapDenylist = "denylist.txt"

    @Parameter(
        names = ["-zmapThreads"],
        required = false,
        description = "How many threads ZMap uses."
    )
    var zmapThreads = 0

    @Parameter(
        names = ["-zmapBandwith"],
        required = false,
        description = "The bandwidth that zmap uses, given in zmap notation. Default to 0. Overrides PPS when specified!"
    )
    var zmapBandwith = "0"

    @Parameter(
        names =  ["-zmapPPS"],
        required = false,
        description = "The sent rate in packets/sec. Defaults to 100,000."
    )
    var zmapPPS = 100000

    @Parameter(
        names = ["-scanUdp"],
        required = false,
        description = "Whether to scan for UDP or TCP Echo servers. Default TCP."
    )
    var scanUdp = false

    @Parameter(
        names = ["-taskPeriod"],
        required = false,
        description = "The period of the task given in ms. Defaults to 1 day."
    )
    var taskPeriod : Long = 86400000

    @Parameter(
        names = ["-echoTestData"],
        required = false,
        description = "The data that is sent as test data for the Echo servers, given in hex. Converted to Byte during sending. Defaults to 41"
    )
    var echoTestData = "41"

    @Parameter(
        names = ["-skipZmap"],
        required = false,
        description = "Can be given to skip ZMap - useful when just the evaluation scan needs to be restarted."
    )
    var skipZmap = false

    @Parameter(
        names = ["-repetitionPeriod"],
        required = false,
        description = "The period of the task given in ms that performs repeating measurements over a day. Defaults to 1 hour."
    )
    var repetitionPeriod : Long = 3600000

    @Parameter(
        names = ["-skipNmap"],
        required = false,
        description = "Can be given to skip NMap."
    )
    var skipNmap = false

    @Parameter(
        names = ["-nmapSampleSize"],
        required = false,
        description = "The sample size for nmap, given in percent. Default: 0.01 (1%)."
    )
    var nmapSampleSize = 0.01

    @Parameter(
        names = ["-nmapInputFileIdentifier"],
        required = false,
        description = "The input file identifier for the nmap input. Appended with date and .txt."
    )
    var nmapInputFileIdentifier = "nmap_input"

    @Parameter(
        names = ["-nmapOutputFileIdentifier"],
        required = false,
        description = "The output file identifier for the nmap output. Appended with date and .txt."
    )
    var nmapOutputFileIdentifier = "nmap_output"

    @Parameter(
        names = ["-skipInitialWait"],
        required = false,
        description = "Whether to skip the default initial waiting time for the next day to start. Defaults to false."
    )
    var skipInitialWait = false

    @ParametersDelegate
    @Transient
    val generalDelegate = GeneralDelegate()

    fun toHumanReadable(): String {
        return "EchoEvalConfig(\n" +
                "timeout=$timeout,\n" +
                "keyLogFile='$keyLogFile',\n" +
                "outputFileIdentifier='$outputFileIdentifier',\n" +
                "networkInterface='$networkInterface',\n" +
                "threads=$threads,\n" +
                "echoIPs=$echoIPs,\n" +
                "zmapInterface='$zmapInterface',\n" +
                "zmapOutputFileIdentifier='$zmapOutputFileIdentifier',\n" +
                "zmapDenylist='$zmapDenylist',\n" +
                "zmapThreads=$zmapThreads,\n" +
                "zmapBandwidth=$zmapBandwith, \n" +
                "zmapPPS=$zmapPPS\n" +
                "scanUdp=$scanUdp\n" +
                "taskPeriod=$taskPeriod,\n" +
                "echoTestData='$echoTestData',\n" +
                "skipZmap=$skipZmap,\n" +
                "repetitionPeriod=$repetitionPeriod,\n" +
                "nmapSampleSize=$nmapSampleSize\n" +
                "skipNmap=$skipNmap,\n" +
                "nmapInputFileIdentifier=$nmapInputFileIdentifier\n" +
                "nmapOutputFileIdentifier=$nmapOutputFileIdentifier\n" +
                "skipInitialWait=$skipInitialWait,\n" +
                "generalDelegate=$generalDelegate,\n"
    }

    override fun apply() {
        generalDelegate.apply()
    }
}