package r5gk.boot.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import r5gk.boot.ModuleItem

/**
 * Module management, laid out like the KernelSU module list: name, version,
 * author, a couple of chips and round icon buttons.  Pull down to refresh.
 *
 * "更新" is the merge step: the installer stages a module in modules_update,
 * and moving it into modules/ is what makes it take effect here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ModuleScreen(
    modules: List<ModuleItem>,
    busy: Boolean,
    acting: Boolean,
    error: String,
    message: String,
    onMessageShown: () -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onAction: (String, ModuleItem) -> Unit,
) {
    var confirmRemove by remember { mutableStateOf<ModuleItem?>(null) }
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(message) {
        if (message.isNotBlank()) {
            snackbar.showSnackbar(message)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("模块") },
                navigationIcon = {
                    TextButton(onClick = onBack) { Text("返回") }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                ),
            )
        },
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = busy,
            onRefresh = onRefresh,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (error.isNotBlank()) {
                    item {
                        Text(
                            error,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                if (modules.isEmpty() && error.isBlank() && !busy) {
                    item {
                        Text(
                            "没有找到模块,按照后请下拉刷新",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                items(modules, key = { it.id }) { item ->
                    ModuleCard(
                        item = item,
                        acting = acting,
                        onAction = onAction,
                        onDelete = { confirmRemove = item },
                    )
                }
            }
        }

        confirmRemove?.let { item ->
            AlertDialog(
                onDismissRequest = { confirmRemove = null },
                title = { Text("卸载 ${item.name}？") },
                text = { Text("删除/data/adb/modules/${item.id}") },
                confirmButton = {
                    TextButton(onClick = {
                        confirmRemove = null
                        onAction("remove", item)
                    }) { Text("删除") }
                },
                dismissButton = {
                    TextButton(onClick = { confirmRemove = null }) { Text("取消") }
                },
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModuleCard(
    item: ModuleItem,
    acting: Boolean,
    onAction: (String, ModuleItem) -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                item.name,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                "版本：" + item.version.ifBlank { "?" },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (item.author.isNotBlank()) {
                Text(
                    "作者：" + item.author,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Chip(formatSize(item.sizeKb))
                if (item.updatable) {
                    Chip("可更新", true)
                }
                Chip(if (item.mounted) "已挂载" else "未挂载", item.mounted)
                when (item.state) {
                    "disabled" -> Chip("已禁用")
                    "pending" -> Chip("待合并")
                    "remove" -> Chip("待删除")
                    else -> Chip("启用", true)
                }
            }

            // Long press a round button to see what it does.
            var tip by remember(item.id) { mutableStateOf("") }
            LaunchedEffect(tip) {
                if (tip.isNotEmpty()) {
                    kotlinx.coroutines.delay(2500)
                    tip = ""
                }
            }
            if (tip.isNotEmpty()) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = MaterialTheme.colorScheme.inverseSurface,
                ) {
                    Text(
                        tip,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.inverseOnSurface,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CircleAction(
                    enabled = item.updatable && !acting,
                    onClick = { onAction("update", item) },
                    onLongClick = {
                        tip = if (item.updatable) {
                            "合并modules_update到modules"
                        } else {
                            "当前没有待合并的版本"
                        }
                    },
                ) {
                    Icon(
                        Icons.Filled.Refresh,
                        contentDescription = "更新",
                        modifier = Modifier.size(20.dp),
                    )
                }
                CircleAction(
                    enabled = !acting,
                    onClick = onDelete,
                    onLongClick = {
                        tip = "完全删除模块"
                    },
                ) {
                    Icon(
                        Icons.Filled.Delete,
                        contentDescription = "卸载",
                        modifier = Modifier.size(20.dp),
                    )
                }
            }
        }
    }
}

/** Round tonal icon button that also reports a long press. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun CircleAction(
    enabled: Boolean,
    onClick: () -> Unit,
    onLongClick: () -> Unit,
    content: @Composable () -> Unit,
) {
    Surface(
        shape = CircleShape,
        color = if (enabled) {
            MaterialTheme.colorScheme.secondaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceVariant
        },
        contentColor = if (enabled) {
            MaterialTheme.colorScheme.onSecondaryContainer
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
        modifier = Modifier
            .size(48.dp)
            .combinedClickable(
                enabled = enabled,
                onClick = onClick,
                onLongClick = onLongClick,
            ),
    ) {
        Box(contentAlignment = Alignment.Center) { content() }
    }
}

@Composable
private fun Chip(text: String, positive: Boolean = false) {
    Surface(
        shape = MaterialTheme.shapes.small,
        color = if (positive) {
            MaterialTheme.colorScheme.secondaryContainer
        } else {
            MaterialTheme.colorScheme.surfaceVariant
        },
    ) {
        Text(
            text,
            style = MaterialTheme.typography.labelMedium,
            color = if (positive) {
                MaterialTheme.colorScheme.onSecondaryContainer
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
        )
    }
}

private fun formatSize(kb: Long): String = when {
    kb <= 0 -> "?"
    kb >= 1024 * 1024 -> String.format("%.1f GB", kb / 1024.0 / 1024.0)
    kb >= 1024 -> String.format("%.2f MB", kb / 1024.0)
    else -> "$kb KB"
}
