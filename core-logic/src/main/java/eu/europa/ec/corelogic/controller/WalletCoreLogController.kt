/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.corelogic.controller

import android.util.Base64
import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.eudi.wallet.logging.Logger
import org.json.JSONObject
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

interface WalletCoreLogController : Logger

class WalletCoreLogControllerImpl(
    private val logController: LogController
) : WalletCoreLogController {

    companion object {
        private const val JWT_LOG_TAG = "EUDI_JWT"
        private const val RESPONSE_JWT_CONTENT_TYPE = "BODY Content-Type: application/oauth-authz-req+jwt"
        private const val RESPONSE_START_MARKER = "BODY START"
        private const val RESPONSE_END_MARKER = "BODY END"
    }

    override fun log(record: Logger.Record) {
        when (record.level) {
            Logger.LEVEL_ERROR -> record.thrown?.let { logController.e(it) }
                ?: logController.e { record.message }

            Logger.LEVEL_INFO -> logController.i { record.message }
            Logger.LEVEL_DEBUG -> {
                logController.d { record.message }
                // added by ewQwe to log additional debug data
                logRequestObjectJwtIfPresent(record.message)
            }
        }
    }

    private fun logRequestObjectJwtIfPresent(message: String) {
        if (!message.contains(RESPONSE_JWT_CONTENT_TYPE)) return

        val jwt = extractBody(message) ?: return
        val parts = jwt.split('.')
        if (parts.size < 2) return

        val headerRaw = decodeJwtPart(parts[0]) ?: return
        val payloadRaw = decodeJwtPart(parts[1]) ?: return

        val headerPretty = headerRaw.toPrettyJsonOrRaw()
        val payloadPretty = payloadRaw.toPrettyJsonOrRaw()

        logController.d(JWT_LOG_TAG) { "Request Object JWT (raw):\n$jwt" }
        logController.d(JWT_LOG_TAG) { "Request Object JWT header:\n$headerPretty" }
        logController.d(JWT_LOG_TAG) { "Request Object JWT payload:\n$payloadPretty" }

        logX5cDetails(headerRaw)
        logClientIdBindingDiagnostics(headerRaw = headerRaw, payloadRaw = payloadRaw)
    }

    private fun extractBody(message: String): String? {
        val startIndex = message.indexOf(RESPONSE_START_MARKER)
        val endIndex = message.indexOf(RESPONSE_END_MARKER)
        if (startIndex < 0 || endIndex <= startIndex) return null

        val rawBody = message.substring(startIndex + RESPONSE_START_MARKER.length, endIndex).trim()
        return rawBody.lines().joinToString(separator = "") { it.trim() }.ifBlank { null }
    }

    private fun decodeJwtPart(part: String): String? {
        return runCatching {
            val normalized = part.padEnd(part.length + ((4 - part.length % 4) % 4), '=')
            val decoded = Base64.decode(normalized, Base64.URL_SAFE or Base64.NO_WRAP)
            decoded.toString(Charsets.UTF_8)
        }.getOrNull()
    }

    private fun String.toPrettyJsonOrRaw(): String {
        return runCatching { JSONObject(this).toString(2) }.getOrDefault(this)
    }

    private fun logX5cDetails(headerRaw: String) {
        val header = runCatching { JSONObject(headerRaw) }.getOrNull() ?: return
        val x5c = header.optJSONArray("x5c") ?: return

        val certFactory = runCatching { CertificateFactory.getInstance("X.509") }.getOrNull() ?: return
        val certCount = x5c.length()
        logController.d(JWT_LOG_TAG) { "x5c certificates: $certCount" }

        repeat(certCount) { index ->
            val certBase64 = x5c.optString(index)
            if (certBase64.isNullOrBlank()) return@repeat

            val cert = runCatching {
                val der = Base64.decode(certBase64, Base64.DEFAULT)
                certFactory.generateCertificate(der.inputStream()) as X509Certificate
            }.getOrNull()

            if (cert == null) {
                logController.d(JWT_LOG_TAG) { "x5c[$index]: could not decode certificate" }
            } else {
                logController.d(JWT_LOG_TAG) {
                    "x5c[$index]: subject=${cert.subjectX500Principal.name}, issuer=${cert.issuerX500Principal.name}, serial=${cert.serialNumber.toString(16)}, notBefore=${cert.notBefore}, notAfter=${cert.notAfter}"
                }
            }
        }
    }

    private fun logClientIdBindingDiagnostics(headerRaw: String, payloadRaw: String) {
        val header = runCatching { JSONObject(headerRaw) }.getOrNull() ?: return
        val payload = runCatching { JSONObject(payloadRaw) }.getOrNull() ?: return

        val clientId = payload.optString("client_id").orEmpty()
        val clientIdScheme = payload.optString("client_id_scheme").orEmpty()
        if (clientId.isBlank()) return

        val x5c = header.optJSONArray("x5c") ?: return
        if (x5c.length() == 0) return

        val leafBase64 = x5c.optString(0)
        if (leafBase64.isBlank()) return

        val computedHash = runCatching {
            val leafDer = Base64.decode(leafBase64, Base64.DEFAULT)
            val digest = MessageDigest.getInstance("SHA-256").digest(leafDer)
            Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        }.getOrNull() ?: return

        // The eudi-lib-jvm-openid4vp-kt does strip the prefix to perform the client_id match
        val strippedClientId = clientId.substringAfter(':', clientId)
        val strippedMatch = strippedClientId == computedHash

        logController.d(JWT_LOG_TAG) {
            "client_id diagnostics: scheme=$clientIdScheme, client_id=$clientId, computed_x5c0_sha256=$computedHash, client_id_match=$strippedMatch"
        }

        if (clientId.contains(':')) {
            logController.d(JWT_LOG_TAG) {
                "client_id contains a prefix separator ':'; stripped client_id candidate=$strippedClientId"
            }
        }
    }
}