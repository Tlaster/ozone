package sh.christian.ozone.api

import app.bsky.actor.GetProfileQueryParams
import app.bsky.actor.GetProfileResponse
import app.bsky.feed.GetTimelineQueryParams
import app.bsky.feed.GetTimelineResponse
import com.atproto.repo.CreateRecordRequest
import com.atproto.repo.CreateRecordResponse
import com.atproto.session.CreateRequest
import com.atproto.session.CreateResponse
import sh.christian.ozone.api.response.AtpResponse

interface AtpApi {
  suspend fun createSession(
    request: CreateRequest,
  ): AtpResponse<CreateResponse>

  suspend fun getTimeline(
    params: GetTimelineQueryParams,
  ): AtpResponse<GetTimelineResponse>

  suspend fun getProfile(
    params: GetProfileQueryParams,
  ): AtpResponse<GetProfileResponse>

  suspend fun createRecord(
    request: CreateRecordRequest,
  ): AtpResponse<CreateRecordResponse>
}
