package sh.christian.ozone.model

import app.bsky.feed.Post
import sh.christian.ozone.util.ReadOnlyList
import sh.christian.ozone.util.mapNotNullImmutable

data class LitePost(
  val text: String,
  val links: ReadOnlyList<TimelinePostLink>,
  val createdAt: Moment,
)

fun Post.toLitePost(): LitePost {
  return LitePost(
    text = text,
    links = facets.mapNotNullImmutable { it.toLinkOrNull() },
    createdAt = Moment(createdAt),
  )
}
