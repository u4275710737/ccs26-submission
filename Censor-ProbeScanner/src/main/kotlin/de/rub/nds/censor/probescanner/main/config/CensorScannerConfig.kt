package de.rub.nds.censor.probescanner.main.config

import com.beust.jcommander.Parameter
import com.beust.jcommander.ParametersDelegate
import de.rub.nds.censor.core.config.Delegate
import de.rub.nds.censor.core.config.GeneralDelegate
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.scanner.core.config.ExecutorConfig
import kotlinx.serialization.Transient
import org.apache.logging.log4j.kotlin.Logging

/**
 * Config for the censor scanner.
 */
class CensorScannerConfig: Delegate, Logging {

    @Parameter(
        names = ["-timeout"],
        required = false,
        description = "The timeout used for the scans in ms"
    )
    var timeout = 5000

    @Parameter(
        names = ["-hostname"],
        required = false,
        description = "The hostname to use for censorship probes"
    )
    var hostname = "www.uyghurnet.org"

    @Parameter(
        names = ["-ip"],
        required = false,
        description = "The IP to use for censorship probes"
    )
    var ip = "185.15.59.224"

    @Parameter(
        names = ["-echo"],
        required = false,
        description = "Whether the probes are executed for the Echo protocol (Port 7)"
    )
    var echo = false

    @Parameter(
        names = ["-path"],
        required = false,
        description = "The path to use for the HTTP path probes"
    )
    var path = "/www.uyghurnet.org"

    @Parameter(
        names = ["-censoredIp"],
        required = false,
        description = "The IP address to use for the IP censorship probe"
    )
    var censoredIp = "172.217.18.14" // Youtube

    @Parameter(
        names = ["-dnsHostname"],
        required = false,
        description = "The hostname to use for DNS-based censorship probes"
    )
    var dnsHostname = "wikipedia.org"

    @Parameter(
        names = ["-mimicClientPort"],
        required = false,
        description = "Mimics the client port depending on the protocol (useful for Echo mode) - e.g., 53 for DNS"
    )
    var mimicClientPort = false

    @ParametersDelegate
    val executorConfig = ExecutorConfig()

    @ParametersDelegate
    @Transient
    val generalDelegate = GeneralDelegate()

    fun getIpAddress(): Ipv4Address {
        return Ipv4Address(ip)
    }

    override fun apply() {
        generalDelegate.apply()
    }

    fun getCensoredIpAsHex() : String {
        var hexString = ""
        censoredIp.split(".").forEach {
            val hex = Integer.toHexString(it.toInt())
            if (hex.length == 1) {
                hexString += "0"
            }
            hexString += hex
        }
        logger.debug("Converted IP $censoredIp to $hexString")
        return hexString
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun getDnsHostnameAsHex() : String {
        var hexString = ""
        dnsHostname.split(".").forEach {
            val lengthHex = Integer.toHexString(it.length)
            if (lengthHex.length == 1) {
                hexString += "0"
            }
            hexString +=  lengthHex// first length, then encoding
            hexString += it.toByteArray(Charsets.ISO_8859_1).toHexString()
        }
        hexString += "00" //termination
        logger.debug("Converted hostname $dnsHostname to $hexString")
        return hexString
    }
}