/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.probescanner.main

import com.beust.jcommander.JCommander
import com.beust.jcommander.ParameterException
import de.rub.nds.censor.probescanner.main.config.CensorScannerConfig
import de.rub.nds.censor.probescanner.main.execution.CensorScanner
import de.rub.nds.censor.probescanner.main.report.CensorReportPrinter
import de.rub.nds.censor.probescanner.main.report.getDefaultPrintingScheme
import de.rub.nds.scanner.core.report.AnsiColor
import org.apache.logging.log4j.LogManager
import java.io.File


fun main(args: Array<String>) {
    val logger = LogManager.getLogger()
    val config = CensorScannerConfig()
    val jCommander = JCommander(config)
    try {
        jCommander.parse(*args)
        config.apply()
    } catch (e: ParameterException) {
        LogManager.getLogger().error(e)
        jCommander.usage()
        return
    }
    config.apply()
    val scanner = CensorScanner(config)
    val time = System.currentTimeMillis()
    logger.info("Performing Scan, this may take some time...")
    val report = scanner.scan()
    logger.info(
        (AnsiColor.RESET.code
                + "Scanned in: ") + (System.currentTimeMillis() - time) / 1000 + "s\n"
                + CensorReportPrinter(
            report,
            config.executorConfig.reportDetail,
            getDefaultPrintingScheme(),
            !config.executorConfig.isNoColor
        )
            .fullReport
    )
    if (config.executorConfig.isWriteReportToFile) {
        val outputFile = File(config.executorConfig.outputFile)
        outputFile.writeText(report.serializeToString())
    }
}