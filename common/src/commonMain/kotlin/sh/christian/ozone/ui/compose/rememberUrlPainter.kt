package sh.christian.ozone.ui.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.painter.BitmapPainter
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.platform.LocalDensity
import io.kamel.core.DataSource
import io.kamel.core.Resource
import io.kamel.core.config.KamelConfig
import io.kamel.core.config.ResourceConfigBuilder
import io.kamel.core.loadImageBitmapResource
import io.kamel.core.loadImageVectorResource
import io.kamel.core.loadSvgResource
import io.kamel.core.map
import io.kamel.image.config.LocalKamelConfig

/**
 * This is a copy of https://github.com/alialbaali/Kamel/pull/33 that can be used instead of
 * `lazyPainterResource` until it's available in a new version.
 *
 * Currently the lazyPainterResource will always result in at least 2 compositions even when the
 * Painter is already cached: the first one always returns Resource.Loading, while the second one
 * is the actual Resource.Success containing the cached Painter.
 *
 * By looking up the cached Painter ahead of time and using that as the initial value if it exists,
 * we skip a recomposition for preloaded Painters and avoid a UI flash in some cases where an
 * external factor causes a recomposition.
 */
@Composable
fun rememberUrlPainter(
  data: Any,
  key: Any? = data,
  filterQuality: FilterQuality = DrawScope.DefaultFilterQuality,
  onLoadingPainter: @Composable (Float) -> Painter? = { null },
  onFailurePainter: @Composable (Throwable) -> Painter? = { null },
  block: ResourceConfigBuilder.() -> Unit = {},
): Resource<Painter> {

  val kamelConfig = LocalKamelConfig.current
  val density = LocalDensity.current
  val resourceConfig = remember(key, density) {
    ResourceConfigBuilder()
      .apply { this.density = density }
      .apply(block)
      .build()
  }

  val cachedOutput = remember(key) {
    val output = kamelConfig.mapInput(data)
    when (data.toString().substringAfterLast(".")) {
      "svg" -> kamelConfig.svgCache[output]?.let { Resource.Success(it, DataSource.Memory) }
      "xml" -> kamelConfig.imageVectorCache[output]?.let { Resource.Success(it, DataSource.Memory) }
      else -> kamelConfig.imageBitmapCache[output]?.let { Resource.Success(it, DataSource.Memory) }
    }
  }

  val painterResource by remember(key, resourceConfig) {
    when (data.toString().substringAfterLast(".")) {
      "svg" -> kamelConfig.loadSvgResource(data, resourceConfig)
      "xml" -> kamelConfig.loadImageVectorResource(data, resourceConfig)
      else -> kamelConfig.loadImageBitmapResource(data, resourceConfig)
    }
  }.collectAsState(cachedOutput ?: Resource.Loading(0F), resourceConfig.coroutineContext)

  val painterResourceWithFallbacks = when (painterResource) {
    is Resource.Loading -> {
      val resource = painterResource as Resource.Loading
      val painter = onLoadingPainter(resource.progress)
      if (painter != null) Resource.Success(painter) else painterResource
    }
    is Resource.Success -> painterResource
    is Resource.Failure -> {
      val resource = painterResource as Resource.Failure
      val painter = onFailurePainter(resource.exception)
      if (painter != null) Resource.Success(painter) else painterResource
    }
  }

  return painterResourceWithFallbacks.map { value ->
    when (value) {
      is ImageVector -> rememberVectorPainter(value)
      is ImageBitmap -> remember(value) {
        BitmapPainter(value, filterQuality = filterQuality)
      }
      else -> remember(value) { value as Painter }
    }
  }
}

private fun KamelConfig.mapInput(input: Any): Any {
  var output: Any? = null
  mappers.findLast {
    output = runCatching { it.map(input) }.getOrNull()
    output != null
  }
  return output ?: input
}
