package app.xio.xio

import androidx.core.content.FileProvider

// Separate Android components keep profile URI grants independent of APK updates.
// Neither provider is exported; only explicitly shared URIs receive read access.
class ProfileFileProvider : FileProvider()
class UpdateFileProvider : FileProvider()
