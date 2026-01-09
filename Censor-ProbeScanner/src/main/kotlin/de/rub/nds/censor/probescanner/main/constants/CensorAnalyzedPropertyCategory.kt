package de.rub.nds.censor.probescanner.main.constants

import de.rub.nds.scanner.core.probe.AnalyzedPropertyCategory

/**
 * Categories of [CensorAnalyzedProperty].
 */
enum class CensorAnalyzedPropertyCategory: AnalyzedPropertyCategory {
    ENCRYPTED_DNS,
    TLS,
    HTTP,
    TCP,
    DNS,
    QUIC
}