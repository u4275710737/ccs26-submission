package de.rub.nds.censor.echo.data

import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.network.Ipv4Address
import kotlinx.serialization.Serializable

/**
 * Serializable data class for storing a map between echo Ipv4Addresses and results.
 */
@Serializable
data class EchoServerResult (
    val echoIP : Ipv4Address,
    var result : ConnectionReturn = ConnectionReturn.UNSET
)