package de.rub.nds.censor.probescanner.main.constants

import de.rub.nds.scanner.core.probe.ProbeType

/**
 * Each probe is assigned a category.
 */
enum class CensorProbeType(private val humanReadableName: String): ProbeType {
    DNS("DNS"),
    TLS("TLS"),
    HTTP("HTTP"),
    TCP("TCP"),
    QUIC("QUIC");

    override fun getName(): String {
        return humanReadableName
    }
}