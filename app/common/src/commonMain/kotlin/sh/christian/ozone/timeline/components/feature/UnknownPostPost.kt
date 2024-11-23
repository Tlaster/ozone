package sh.christian.ozone.timeline.components.feature

import androidx.compose.runtime.Composable

@Composable
fun UnknownPostPost(onClick: (() -> Unit)?) {
  FeatureContainer(onClick = onClick) {
    PostFeatureTextContent(
      title = "Unknown post",
      description = "This post cannot be viewed.",
      uri = null,
    )
  }
}
