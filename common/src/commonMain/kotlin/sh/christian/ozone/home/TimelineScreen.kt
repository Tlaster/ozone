package sh.christian.ozone.home

import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExitToApp
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.text.font.FontWeight.Companion.Bold
import androidx.compose.ui.unit.dp
import app.bsky.actor.ProfileView
import app.bsky.feed.FeedViewPost
import kotlinx.coroutines.launch
import kotlinx.datetime.Instant
import sh.christian.ozone.ui.compose.AvatarImage
import sh.christian.ozone.ui.compose.OpenImageAction
import sh.christian.ozone.ui.workflow.ViewRendering
import sh.christian.ozone.ui.workflow.screen

@OptIn(ExperimentalMaterial3Api::class)
class TimelineScreen(
  private val now: Instant,
  private val profile: ProfileView?,
  private val timeline: List<FeedViewPost>,
  private val onSignOut: () -> Unit,
  private val onExit: () -> Unit,
  private val onOpenImage: (OpenImageAction) -> Unit,
) : ViewRendering by screen({
  val feedState = rememberLazyListState()
  val coroutineScope = rememberCoroutineScope()

  Scaffold(
    modifier = Modifier.fillMaxSize(),
    topBar = {
      CenterAlignedTopAppBar(
        navigationIcon = {
          Box(Modifier.padding(start = 12.dp)) {
            AvatarImage(
              modifier = Modifier.size(32.dp),
              avatarUrl = profile?.avatar,
              onClick = { },
              contentDescription = profile?.displayName ?: profile?.handle,
              fallbackColor = Color.Black,
            )
          }
        },
        title = {
          Text(
            modifier = Modifier.clickable(
              indication = null,
              interactionSource = remember { MutableInteractionSource() },
              onClick = {
                coroutineScope.launch {
                  if (feedState.isScrollInProgress) {
                    // If scrolling already (either via animateScrollToItem or fling), snap to top.
                    feedState.scrollToItem(0)
                  } else {
                    // Otherwise, smoothly scroll to the top.
                    feedState.animateScrollToItem(0)
                  }
                }
              },
            ),
            text = "Ozone",
            style = MaterialTheme.typography.titleLarge.copy(fontWeight = Bold),
          )
        },
        actions = {
          IconButton(onClick = onSignOut) {
            Icon(
              painter = rememberVectorPainter(Icons.Default.ExitToApp),
              contentDescription = "Sign Out",
            )
          }
        }
      )
    },
  ) { contentPadding ->
    Box(modifier = Modifier.padding(contentPadding).fillMaxSize()) {
      LazyColumn(
        modifier = Modifier.fillMaxSize(),
        state = feedState,
      ) {
        items(items = timeline, key = { it.post.cid }) { post ->
          TimelinePost(now, post.post, post.reply, onOpenImage)
        }
      }
    }
  }
})
