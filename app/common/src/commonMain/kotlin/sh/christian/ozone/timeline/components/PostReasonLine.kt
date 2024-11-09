package sh.christian.ozone.timeline.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement.spacedBy
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.unit.dp
import sh.christian.ozone.model.TimelinePostReason
import sh.christian.ozone.model.TimelinePostReason.TimelinePostPin
import sh.christian.ozone.model.TimelinePostReason.TimelinePostRepost
import sh.christian.ozone.ui.icons.Repeat
import sh.christian.ozone.user.UserDid
import sh.christian.ozone.user.UserReference

@Composable
internal fun PostReasonLine(
  reason: TimelinePostReason?,
  onOpenUser: (UserReference) -> Unit,
) {
  when (reason) {
    is TimelinePostRepost -> PostRepostReasonLine(reason, onOpenUser)
    is TimelinePostPin -> PostPinnedReasonLine()
    null -> Unit
  }
}

@Composable
private fun PostRepostReasonLine(
  reason: TimelinePostRepost,
  onOpenUser: (UserReference) -> Unit,
) {
  PostReasonLine(
    modifier = Modifier.clickable { onOpenUser(UserDid(reason.repostAuthor.did)) },
    iconPainter = rememberVectorPainter(Icons.Default.Repeat),
    iconContentDescription = "Repost",
    text = "Reposted by ${reason.repostAuthor.displayName ?: reason.repostAuthor.handle}",
  )
}

@Composable
private fun PostPinnedReasonLine() {
  PostReasonLine(
    iconPainter = rememberVectorPainter(Icons.Default.Star),
    iconContentDescription = "Pinned",
    text = "Pinned",
  )
}

@Composable
private fun PostReasonLine(
  modifier: Modifier = Modifier,
  iconPainter: Painter,
  iconContentDescription: String,
  text: String,
) {
  Row(
    modifier = modifier,
    verticalAlignment = Alignment.CenterVertically,
    horizontalArrangement = spacedBy(4.dp),
  ) {
    Icon(
      modifier = Modifier.size(12.dp),
      painter = iconPainter,
      contentDescription = iconContentDescription,
      tint = MaterialTheme.typography.bodySmall.color,
    )

    Text(
      text = text,
      maxLines = 1,
      style = MaterialTheme.typography.bodySmall,
    )
  }
}
