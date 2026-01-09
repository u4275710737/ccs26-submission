package de.rub.nds.censor.probescanner.main.report

import de.rub.nds.censor.probescanner.main.constants.CensorAnalyzedProperty
import de.rub.nds.scanner.core.config.ScannerDetail
import de.rub.nds.scanner.core.probe.result.TestResults
import de.rub.nds.scanner.core.report.PrintingScheme
import de.rub.nds.scanner.core.report.ReportPrinter
import java.lang.StringBuilder

/**
 * Prints the [CensorReport] in human-readable form.
 */
class CensorReportPrinter(report: CensorReport, detail: ScannerDetail, scheme: PrintingScheme, printColorful: Boolean): ReportPrinter<CensorReport>(detail, scheme, printColorful, report) {

    override fun getFullReport(): String {
        val builder = StringBuilder()
        appendEncryptedDns(builder)
        return builder.toString()
    }

    private fun appendEncryptedDns(builder: StringBuilder) {
        val blocksDoT = report.getResult(CensorAnalyzedProperty.BLOCKS_DOT)
        val blocksDoH = report.getResult(CensorAnalyzedProperty.BLOCKS_DOH)
        prettyAppendHeading(builder, "DoT / DoH")

        prettyAppend(builder, "Blocks DoT", CensorAnalyzedProperty.BLOCKS_DOT)
        if (blocksDoT == TestResults.TRUE) {
            prettyAppend(builder, "  Blocked DNS servers:")
            report.getBlockedDoTServers()?.forEach {
                builder.append("\n    ").append(it)
            }
            builder.append("\n\n")
        }

        prettyAppend(builder, "Blocks DoH", CensorAnalyzedProperty.BLOCKS_DOH)
        if (blocksDoH == TestResults.TRUE) {
            prettyAppend(builder, "  Blocked DNS servers:")
            report.getBlockedDoHServers()?.forEach {
                builder.append("\n    ").append(it)
            }
            builder.append("\n\n")
        }

        prettyAppend(builder, "Blocks SNI", CensorAnalyzedProperty.BLOCKS_SNI)
        prettyAppend(builder, "Blocks ESNI", CensorAnalyzedProperty.BLOCKS_ESNI)
        prettyAppend(builder, "Blocks ECH", CensorAnalyzedProperty.BLOCKS_ECH)
        prettyAppend(builder, "Blocks HTTP(Path)", CensorAnalyzedProperty.BLOCKS_PATH)
        prettyAppend(builder, "Blocks HTTP(Host)", CensorAnalyzedProperty.BLOCKS_HOST)
        prettyAppend(builder, "Blocks HTTP(Response)", CensorAnalyzedProperty.BLOCKS_RESPONSE)
        prettyAppend(builder, "Blocks TCP/IP in TCP", CensorAnalyzedProperty.BLOCKS_TCP)
        prettyAppend(builder, "Blocks DNS Request", CensorAnalyzedProperty.BLOCKS_DNS_REQUEST)
        prettyAppend(builder, "Blocks DNS Response", CensorAnalyzedProperty.BLOCKS_DNS_RESPONSE)
        prettyAppend(builder, "Blocks QUIC SNI", CensorAnalyzedProperty.BLOCKS_QUIC)
    }
}