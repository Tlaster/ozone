package sh.christian.ozone.oauth

import io.ktor.http.URLProtocol
import io.ktor.http.Url
import io.ktor.http.buildUrl
import io.ktor.util.decodeBase64String
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import sh.christian.ozone.api.Did
import kotlin.time.Duration

/**
 * Represents an OAuth token received after a successful authorization or refresh request.
 *
 * @param accessToken The access token used to authenticate API requests.
 * @param refreshToken The refresh token used to obtain a new access token when the current one expires.
 * @param keyPair The DPoP key pair used for signing requests.
 * @param expiresIn The duration for which the access token is valid.
 * @param scopes The list of scopes granted to the access token.
 * @param subject The DID of the user account associated with the token.
 * @param nonce A unique string to prevent replay attacks, typically used in conjunction with DPoP.
 * @param clientId The unique identifier for the OAuth client.
 * @param pdsUrl The URL of the PDS (Personal Data Server) to use for authenticated resource requests.
 */
@Serializable
data class OAuthToken(
  val accessToken: String,
  val refreshToken: String,
  val keyPair: DpopKeyPair,
  val expiresIn: Duration,
  val scopes: List<OAuthScope>,
  val subject: Did,
  val nonce: String,
  val clientId: String = accessToken.payloadClaim("client_id").orEmpty(),
  val pdsUrl: String = accessToken.pdsUrlFromAudienceClaim().orEmpty(),
) {
  /**
   * The audience of the JWT, when the access token happens to be a JWT.
   *
   * OAuth access tokens are opaque from the client's perspective. This value is only provided for compatibility with
   * older tokens that did not persist [pdsUrl].
   */
  val audience: String by lazy {
    requirePayload("aud")
  }

  /**
   * The URL of the PDS (Personal Data Server) associated with the audience.
   */
  val pds: Url by lazy {
    pdsUrl.takeIf { it.isNotBlank() }?.let(::Url)
      ?: audience.toPdsUrl()
  }

  private val payloadJson: JsonObject? by lazy {
    accessToken.payloadJson()
  }

  private fun requirePayload(key: String): String {
    return requireNotNull(payloadJson?.stringClaim(key)) {
      "JWT payload does not contain '$key' claim"
    }
  }
}

private fun String.pdsUrlFromAudienceClaim(): String? {
  return payloadClaim("aud")?.toPdsUrl()?.toString()
}

private fun String.payloadClaim(key: String): String? {
  return payloadJson()?.stringClaim(key)
}

private fun String.payloadJson(): JsonObject? {
  val payloadJwt = split(".").getOrNull(1) ?: return null
  return runCatching {
    Json.decodeFromString(JsonObject.serializer(), payloadJwt.decodeBase64String())
  }.getOrNull()
}

private fun JsonObject.stringClaim(key: String): String? {
  return this[key]?.let { (it as? JsonPrimitive)?.contentOrNull }
}

private fun String.toPdsUrl(): Url {
  return runCatching { Url(this) }
    .getOrElse {
      val did = Did(this)
      buildUrl {
        protocol = URLProtocol.HTTPS
        host = did.toString().substringAfterLast(":")
      }
    }
}
