package sh.christian.ozone

import android.graphics.Color
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import dev.marcellogalhardo.retained.activity.retain
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import sh.christian.ozone.di.AppComponent
import sh.christian.ozone.di.create
import sh.christian.ozone.store.storage
import sh.christian.ozone.ui.AppTheme
import sh.christian.ozone.ui.compose.fontsAssetManager
import sh.christian.ozone.ui.compose.initTypography
import sh.christian.ozone.ui.workflow.WorkflowRendering

class MainActivity : AppCompatActivity() {

  private val appComponent by retain { AppComponent::class.create(storage) }
  private val workflow by lazy { appComponent.appWorkflow }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    window?.statusBarColor = Color.TRANSPARENT
    WindowCompat.setDecorFitsSystemWindows(window, false)

    appComponent.supervisors.forEach { supervisor ->
      with(supervisor) {
        lifecycleScope.launch(SupervisorJob()) { start() }
      }
    }

    runBlocking {
      // Ensure that this is set up before we actually use it in the theme.
      fontsAssetManager = assets
      initTypography()
    }

    setContent {
      AppTheme {
        StatusBarTheme()
        WorkflowRendering(
          workflow = workflow,
          onOutput = { finish() },
          content = { it.Content() },
        )
      }
    }
  }
}