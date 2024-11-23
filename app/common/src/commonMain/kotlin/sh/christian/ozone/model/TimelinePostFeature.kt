package sh.christian.ozone.model

import app.bsky.embed.ExternalView
import app.bsky.embed.ImagesView
import app.bsky.embed.RecordViewRecordUnion
import app.bsky.embed.RecordWithMediaViewMediaUnion
import app.bsky.feed.Post
import app.bsky.feed.PostViewEmbedUnion
import kotlinx.collections.immutable.ImmutableList
import sh.christian.ozone.api.AtUri
import sh.christian.ozone.api.Cid
import sh.christian.ozone.api.Uri
import sh.christian.ozone.model.EmbedPost.BlockedEmbedPost
import sh.christian.ozone.model.EmbedPost.InvisibleEmbedPost
import sh.christian.ozone.model.EmbedPost.UnknownEmbedPost
import sh.christian.ozone.model.EmbedPost.VisibleEmbedPost
import sh.christian.ozone.model.TimelinePostFeature.ExternalFeature
import sh.christian.ozone.model.TimelinePostFeature.ImagesFeature
import sh.christian.ozone.model.TimelinePostFeature.MediaPostFeature
import sh.christian.ozone.model.TimelinePostFeature.PostFeature
import sh.christian.ozone.util.deserialize
import sh.christian.ozone.util.mapImmutable

sealed interface TimelinePostFeature {
  data class ImagesFeature(
    val images: ImmutableList<EmbedImage>,
  ) : TimelinePostFeature, TimelinePostMedia

  data class ExternalFeature(
    val uri: Uri,
    val title: String,
    val description: String,
    val thumb: String?,
  ) : TimelinePostFeature, TimelinePostMedia

  data class PostFeature(
    val post: EmbedPost,
  ) : TimelinePostFeature

  data class MediaPostFeature(
    val post: EmbedPost,
    val media: TimelinePostMedia,
  ) : TimelinePostFeature
}

sealed interface TimelinePostMedia

data class EmbedImage(
  val thumb: String,
  val fullsize: String,
  val alt: String,
)

sealed interface EmbedPost {
  data class VisibleEmbedPost(
    val uri: AtUri,
    val cid: Cid,
    val author: Profile,
    val litePost: LitePost,
  ) : EmbedPost {
    val reference: Reference = Reference(uri, cid)
  }

  data class InvisibleEmbedPost(
    val uri: AtUri,
  ) : EmbedPost

  data class BlockedEmbedPost(
    val uri: AtUri,
  ) : EmbedPost

  data object UnknownEmbedPost : EmbedPost
}

fun PostViewEmbedUnion.toFeature(): TimelinePostFeature? {
  return when (this) {
    is PostViewEmbedUnion.ImagesView -> {
      value.toImagesFeature()
    }
    is PostViewEmbedUnion.ExternalView -> {
      value.toExternalFeature()
    }
    is PostViewEmbedUnion.RecordView -> {
      PostFeature(
        post = value.record.toEmbedPost(),
      )
    }
    is PostViewEmbedUnion.RecordWithMediaView -> {
      MediaPostFeature(
        post = value.record.record.toEmbedPost(),
        media = when (val media = value.media) {
          is RecordWithMediaViewMediaUnion.ExternalView -> media.value.toExternalFeature()
          is RecordWithMediaViewMediaUnion.ImagesView -> media.value.toImagesFeature()
          is RecordWithMediaViewMediaUnion.VideoView -> return null
          is RecordWithMediaViewMediaUnion.Unknown -> return null
        },
      )
    }
    // TODO properly support video views.
    is PostViewEmbedUnion.VideoView -> null
    is PostViewEmbedUnion.Unknown -> null
  }
}

private fun ImagesView.toImagesFeature(): ImagesFeature {
  return ImagesFeature(
    images = images.mapImmutable {
      EmbedImage(
        thumb = it.thumb.uri,
        fullsize = it.fullsize.uri,
        alt = it.alt,
      )
    }
  )
}

private fun ExternalView.toExternalFeature(): ExternalFeature {
  return ExternalFeature(
    uri = external.uri,
    title = external.title,
    description = external.description,
    thumb = external.thumb?.uri,
  )
}

private fun RecordViewRecordUnion.toEmbedPost(): EmbedPost {
  return when (this) {
    is RecordViewRecordUnion.ViewBlocked -> {
      BlockedEmbedPost(
        uri = value.uri,
      )
    }
    is RecordViewRecordUnion.ViewNotFound -> {
      InvisibleEmbedPost(
        uri = value.uri,
      )
    }
    is RecordViewRecordUnion.ViewRecord -> {
      // TODO verify via recordType before blindly deserialized.
      val litePost = Post.serializer().deserialize(value.value).toLitePost()

      VisibleEmbedPost(
        uri = value.uri,
        cid = value.cid,
        author = value.author.toProfile(),
        litePost = litePost,
      )
    }
    is RecordViewRecordUnion.FeedGeneratorView -> {
      // TODO support generator views.
      InvisibleEmbedPost(
        uri = value.uri,
      )
    }
    is RecordViewRecordUnion.GraphListView -> {
      // TODO support graph list views.
      InvisibleEmbedPost(
        uri = value.uri,
      )
    }
    is RecordViewRecordUnion.LabelerLabelerView -> {
      // TODO support labeler views.
      InvisibleEmbedPost(
        uri = value.uri,
      )
    }
    is RecordViewRecordUnion.GraphStarterPackViewBasic -> {
      // TODO support starter pack views.
      InvisibleEmbedPost(
        uri = value.uri,
      )
    }
    is RecordViewRecordUnion.ViewDetached -> {
      // TODO support detached views.
      InvisibleEmbedPost(
        uri = value.uri,
      )
    }
    is RecordViewRecordUnion.Unknown -> {
      UnknownEmbedPost
    }
  }
}
