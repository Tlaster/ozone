package sh.christian.ozone.model

import app.bsky.actor.ProfileView
import app.bsky.actor.ProfileViewBasic
import app.bsky.actor.ProfileViewDetailed
import kotlinx.serialization.Serializable
import sh.christian.ozone.api.Did
import sh.christian.ozone.api.Handle
import sh.christian.ozone.util.ReadOnlyList
import sh.christian.ozone.util.mapImmutable

@Serializable
sealed interface Profile {
  val did: Did
  val handle: Handle
  val displayName: String?
  val avatar: String?
  val mutedByMe: Boolean
  val followingMe: Boolean
  val followedByMe: Boolean
  val labels: ReadOnlyList<Label>
}

@Serializable
data class LiteProfile(
  override val did: Did,
  override val handle: Handle,
  override val displayName: String?,
  override val avatar: String?,
  override val mutedByMe: Boolean,
  override val followingMe: Boolean,
  override val followedByMe: Boolean,
  override val labels: ReadOnlyList<Label>,
) : Profile

@Serializable
data class FullProfile(
  override val did: Did,
  override val handle: Handle,
  override val displayName: String?,
  val description: String?,
  override val avatar: String?,
  val banner: String?,
  val followersCount: Long,
  val followsCount: Long,
  val postsCount: Long,
  val indexedAt: Moment?,
  override val mutedByMe: Boolean,
  override val followingMe: Boolean,
  override val followedByMe: Boolean,
  override val labels: ReadOnlyList<Label>,
) : Profile

fun ProfileViewDetailed.toProfile(): FullProfile {
  return FullProfile(
    did = did,
    handle = handle,
    displayName = displayName,
    description = description,
    avatar = avatar?.uri,
    banner = banner?.uri,
    followersCount = followersCount ?: 0,
    followsCount = followsCount ?: 0,
    postsCount = postsCount ?: 0,
    indexedAt = indexedAt?.let(::Moment),
    mutedByMe = viewer?.muted == true,
    followingMe = viewer?.followedBy != null,
    followedByMe = viewer?.following != null,
    labels = labels.mapImmutable { it.toLabel() },
  )
}

fun ProfileViewBasic.toProfile(): Profile {
  return LiteProfile(
    did = did,
    handle = handle,
    displayName = displayName,
    avatar = avatar?.uri,
    mutedByMe = viewer?.muted != null,
    followingMe = viewer?.followedBy != null,
    followedByMe = viewer?.following != null,
    labels = labels.mapImmutable { it.toLabel() },
  )
}

fun ProfileView.toProfile(): Profile {
  return LiteProfile(
    did = did,
    handle = handle,
    displayName = displayName,
    avatar = avatar?.uri,
    mutedByMe = viewer?.muted == true,
    followingMe = viewer?.followedBy != null,
    followedByMe = viewer?.following != null,
    labels = labels.mapImmutable { it.toLabel() },
  )
}
