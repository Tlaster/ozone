package sh.christian.ozone.api

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import sh.christian.ozone.api.xrpc.Tokens
import sh.christian.ozone.api.xrpc.XrpcApi
import sh.christian.ozone.app.Supervisor
import sh.christian.ozone.login.LoginRepository
import sh.christian.ozone.login.auth.AuthInfo

class ApiProvider(
  private val apiRepository: ServerRepository,
  private val loginRepository: LoginRepository,
) : Supervisor {

  private val host = MutableStateFlow(apiRepository.server.host)
  private val auth = MutableStateFlow(loginRepository.auth?.toTokens())

  private val _api: XrpcApi = XrpcApi(host, auth)
  val api: AtpApi get() = _api

  override suspend fun CoroutineScope.onStart() {
    coroutineScope {
      launch(Dispatchers.IO) {
        apiRepository.server().map { it.host }
          .distinctUntilChanged()
          .collect(host)
      }

      launch(Dispatchers.IO) {
        loginRepository.auth().map { it?.toTokens() }
          .distinctUntilChanged()
          .collect(auth)
      }

      launch(Dispatchers.IO) {
        auth.collect { tokens ->
          if (tokens != null) {
            loginRepository.auth = loginRepository.auth().first()!!.withTokens(tokens)
          } else {
            loginRepository.auth = null
          }
        }
      }
    }
  }

  private fun AuthInfo.toTokens() = Tokens(accessJwt, refreshJwt)

  private fun AuthInfo.withTokens(tokens: Tokens) = copy(
    accessJwt = tokens.auth,
    refreshJwt = tokens.refresh,
  )
}
