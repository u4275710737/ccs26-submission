package de.rub.nds.censor.probescanner.main.report

import de.rub.nds.scanner.core.probe.AnalyzedProperty
import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory
import de.rub.nds.scanner.core.probe.result.TestResult
import de.rub.nds.scanner.core.probe.result.TestResults
import de.rub.nds.scanner.core.report.*

/**
 * Sets the printing scheme for the [CensorReportPrinter]
 */
fun getDefaultPrintingScheme(): PrintingScheme {
    val textEncodingMap = java.util.HashMap<TestResult, String>()
    textEncodingMap[TestResults.CANNOT_BE_TESTED] = "cannot be tested"
    textEncodingMap[TestResults.COULD_NOT_TEST] = "could not test"
    textEncodingMap[TestResults.ERROR_DURING_TEST] = "error"
    textEncodingMap[TestResults.FALSE] = "false"
    textEncodingMap[TestResults.NOT_TESTED_YET] = "not tested yet"
    textEncodingMap[TestResults.TIMEOUT] = "timeout"
    textEncodingMap[TestResults.TRUE] = "true"
    textEncodingMap[TestResults.UNCERTAIN] = "uncertain"
    textEncodingMap[TestResults.UNSUPPORTED] = "unsupported by tls-scanner"
    textEncodingMap[TestResults.PARTIALLY] = "partially"

    val ansiColorMap = java.util.HashMap<TestResult, AnsiColor>()
    ansiColorMap[TestResults.COULD_NOT_TEST] = AnsiColor.BLUE
    ansiColorMap[TestResults.ERROR_DURING_TEST] = AnsiColor.RED_BACKGROUND
    ansiColorMap[TestResults.UNASSIGNED_ERROR] = AnsiColor.RED_BACKGROUND
    ansiColorMap[TestResults.FALSE] = AnsiColor.DEFAULT_COLOR
    ansiColorMap[TestResults.NOT_TESTED_YET] = AnsiColor.WHITE
    ansiColorMap[TestResults.TIMEOUT] = AnsiColor.PURPLE_BACKGROUND
    ansiColorMap[TestResults.TRUE] = AnsiColor.DEFAULT_COLOR
    ansiColorMap[TestResults.UNCERTAIN] = AnsiColor.YELLOW_BACKGROUND
    ansiColorMap[TestResults.UNSUPPORTED] = AnsiColor.CYAN

    val defaultTextEncoding = TestResultTextEncoder(textEncodingMap)
    val defaultColorEncoding = ColorEncoding(ansiColorMap)

    val colorMap = HashMap<AnalyzedProperty, ColorEncoding>()
    val textMap = HashMap<AnalyzedPropertyCategory, TestResultTextEncoder>()
    val specialTextMap = HashMap<AnalyzedProperty, TestResultTextEncoder>()

    return PrintingScheme(
        colorMap,
        textMap,
        defaultTextEncoding,
        defaultColorEncoding,
        specialTextMap,
        HashMap<AnalyzedProperty, Encoder<AnalyzedProperty>>()
    )
}

fun getDefaultColorEncoding(trueColor: AnsiColor, falseColor: AnsiColor): ColorEncoding {

    val colorMap = HashMap<TestResult, AnsiColor>()
    colorMap[TestResults.CANNOT_BE_TESTED] = AnsiColor.WHITE
    colorMap[TestResults.COULD_NOT_TEST] = AnsiColor.BLUE
    colorMap[TestResults.ERROR_DURING_TEST] = AnsiColor.RED_BACKGROUND
    colorMap[TestResults.UNASSIGNED_ERROR] = AnsiColor.RED_BACKGROUND
    colorMap[TestResults.FALSE] = falseColor
    colorMap[TestResults.NOT_TESTED_YET] = AnsiColor.WHITE
    colorMap[TestResults.TIMEOUT] = AnsiColor.PURPLE_BACKGROUND
    colorMap[TestResults.TRUE] = trueColor
    colorMap[TestResults.UNCERTAIN] = AnsiColor.YELLOW_BACKGROUND
    colorMap[TestResults.UNSUPPORTED] = AnsiColor.CYAN
    colorMap[TestResults.PARTIALLY] = AnsiColor.YELLOW
    return ColorEncoding(colorMap)
    }

