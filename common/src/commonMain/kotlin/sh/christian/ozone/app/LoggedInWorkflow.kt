package sh.christian.ozone.app

import app.bsky.actor.GetProfileQueryParams
import app.bsky.actor.GetProfileResponse
import app.bsky.actor.ProfileView
import app.bsky.feed.GetTimelineQueryParams
import app.bsky.feed.GetTimelineResponse
import com.squareup.workflow1.Snapshot
import com.squareup.workflow1.StatefulWorkflow
import com.squareup.workflow1.Worker
import com.squareup.workflow1.action
import com.squareup.workflow1.runningWorker
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.datetime.Clock
import sh.christian.ozone.api.ApiProvider
import sh.christian.ozone.api.response.AtpResponse
import sh.christian.ozone.app.LoggedInOutput.CloseApp
import sh.christian.ozone.app.LoggedInOutput.SignOut
import sh.christian.ozone.app.LoggedInState.FetchingTimeline
import sh.christian.ozone.app.LoggedInState.ShowingError
import sh.christian.ozone.app.LoggedInState.ShowingFullSizeImage
import sh.christian.ozone.app.LoggedInState.ShowingTimeline
import sh.christian.ozone.error.ErrorOutput
import sh.christian.ozone.error.ErrorProps
import sh.christian.ozone.error.ErrorWorkflow
import sh.christian.ozone.error.toErrorProps
import sh.christian.ozone.home.TimelineScreen
import sh.christian.ozone.ui.compose.ImageOverlayScreen
import sh.christian.ozone.ui.compose.TextOverlayScreen
import sh.christian.ozone.ui.workflow.Dismissable
import sh.christian.ozone.ui.workflow.Dismissable.DismissHandler

class LoggedInWorkflow(
  private val clock: Clock,
  private val apiProvider: ApiProvider,
  private val errorWorkflow: ErrorWorkflow,
) : StatefulWorkflow<LoggedInProps, LoggedInState, LoggedInOutput, AppScreen>() {

  override fun initialState(
    props: LoggedInProps,
    snapshot: Snapshot?,
  ): LoggedInState = FetchingTimeline(profile = null, timeline = null)

  override fun render(
    renderProps: LoggedInProps,
    renderState: LoggedInState,
    context: RenderContext
  ): AppScreen = when (renderState) {
    is FetchingTimeline -> {
      context.runningWorker(loadTimeline(renderProps.authInfo.handle)) { result ->
        action {
          val profile = result.profile.maybeResponse()
          val timeline = result.timeline.maybeResponse()

          state = if (profile != null && timeline != null) {
            ShowingTimeline(profile, timeline)
          } else if (profile != null) {
            val errorProps = (result.timeline as AtpResponse.Failure).toErrorProps(true)
              ?: ErrorProps.CustomError("Oops.", "Could not load timeline.", true)

            ShowingError(profile, null, errorProps)
          } else if (timeline != null) {
            val errorProps = (result.profile as AtpResponse.Failure).toErrorProps(true)
              ?: ErrorProps.CustomError("Oops.", "Could not load profile.", true)

            ShowingError(null, timeline, errorProps)
          } else {
            val errorProps = (result.profile as AtpResponse.Failure).toErrorProps(true)
              ?: (result.timeline as AtpResponse.Failure).toErrorProps(true)
              ?: ErrorProps.CustomError("Oops.", "Something bad happened", true)

            ShowingError(null, null, errorProps)
          }
        }
      }
      AppScreen(
        main = context.timelineScreen(renderState.profile, renderState.timeline),
        overlay = TextOverlayScreen(
          onDismiss = Dismissable.Ignore,
          text = "Loading timeline for ${renderProps.authInfo.handle}...",
        )
      )
    }
    is ShowingTimeline -> {
      AppScreen(context.timelineScreen(renderState.profile, renderState.timeline))
    }
    is ShowingFullSizeImage -> {
      AppScreen(
        context.timelineScreen(renderState.profile, renderState.timeline),
        ImageOverlayScreen(
          onDismiss = DismissHandler(
            context.eventHandler { state = renderState.previousState }
          ),
          action = renderState.openImageAction,
        )
      )
    }
    is ShowingError -> {
      AppScreen(
        main = context.timelineScreen(renderState.profile, renderState.timeline),
        overlay = context.renderChild(errorWorkflow, renderState.errorProps) { output ->
          action {
            val oldProfile = state.profile
            val oldTimeline = state.timeline
            when (output) {
              ErrorOutput.Dismiss -> {
                if (oldTimeline == null && oldProfile == null) {
                  setOutput(SignOut)
                } else if (oldTimeline == null || oldProfile == null) {
                  state = FetchingTimeline(oldProfile, oldTimeline)
                } else {
                  state = ShowingTimeline(oldProfile, oldTimeline)
                }
              }
              ErrorOutput.Retry -> state = FetchingTimeline(oldProfile, oldTimeline)
            }
          }
        }
      )
    }
  }

  override fun snapshotState(state: LoggedInState): Snapshot? = null

  private fun RenderContext.timelineScreen(
    profile: ProfileView?,
    timelineResponse: GetTimelineResponse?,
  ): TimelineScreen {
    return TimelineScreen(
      now = clock.now(),
      profile = profile,
      timeline = timelineResponse?.feed.orEmpty(),
      onOpenImage = eventHandler { action ->
        state = ShowingFullSizeImage(state, action)
      },
      onSignOut = eventHandler {
        setOutput(SignOut)
      },
      onExit = eventHandler {
        setOutput(CloseApp)
      },
    )
  }

  private fun loadTimeline(handle: String): Worker<HomePayload> {
    return Worker.from {
      coroutineScope {
        val profile = async { apiProvider.api.getProfile(GetProfileQueryParams(handle)) }
        val timeline = async { apiProvider.api.getTimeline(GetTimelineQueryParams(limit = 100)) }

        HomePayload(profile.await(), timeline.await())
      }
    }
  }

  private data class HomePayload(
    val profile: AtpResponse<GetProfileResponse>,
    val timeline: AtpResponse<GetTimelineResponse>,
  )
}
