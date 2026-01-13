package de.rub.nds.censor.probescanner.main.report

import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.module.SimpleModule
import de.rub.nds.censor.probescanner.main.constants.CensorAnalyzedProperty
import de.rub.nds.censor.core.constants.Ip
import de.rub.nds.scanner.core.report.ScanReport
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigDecimal
import java.nio.charset.Charset

/**
 * Holds all results of the scan.
 */
class CensorReport: ScanReport() {

    fun getBlockedDoHServers(): List<Ip>? {
        return getListResult(CensorAnalyzedProperty.BLOCKED_DOH_SERVERS, Ip::class.java)?.list
    }

    fun getBlockedDoTServers(): List<Ip>? {
        return getListResult(CensorAnalyzedProperty.BLOCKED_DOT_SERVERS, Ip::class.java)?.list
    }

    fun serializeToString(): String {
        return ByteArrayOutputStream().run {
            serializeToJson(this)
            this.toString()
        }
    }

    override fun serializeToJson(outputStream: OutputStream?) {
        val module = SimpleModule()
        val mapper = ObjectMapper()
        mapper.registerModule(module)
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
        mapper.configOverride(BigDecimal::class.java).format = JsonFormat.Value.forShape(JsonFormat.Shape.STRING)
        return mapper.writeValue(outputStream, this)
    }
}