package r5gk.boot.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import r5gk.boot.BootPhase

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    phase: BootPhase,
    status: String,
    ticker: List<String>,
    rows: List<Pair<String, String>>,
    log: String,
    needsShizukuGrant: Boolean,
    showShizuku: Boolean,
    showRootGuide: Boolean,
    onDismissRootGuide: () -> Unit,
    onRootGuideManager: () -> Unit,
    onStart: () -> Unit,
    onManager: () -> Unit,
    onSelfCheck: () -> Unit,
    onShizuku: () -> Unit,
    onGrant: () -> Unit,
    onClearLog: () -> Unit,
    onZygote: () -> Unit,
    onLsposed: () -> Unit,
    onModules: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val running = phase == BootPhase.RUNNING
    // null, "zygote" or "lsposed": which action is waiting for confirmation.
    var ask by remember { mutableStateOf<String?>(null) }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Kagerou", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "AQUOS R5G 临时 Root 引导",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            PersistentPartitionWarning()
            StatusCard(phase = phase, status = status, ticker = ticker)
            Actions(
                running = running,
                needsShizukuGrant = needsShizukuGrant,
                showShizuku = showShizuku,
                onStart = onStart,
                onManager = onManager,
                onSelfCheck = onSelfCheck,
                onShizuku = onShizuku,
                onGrant = onGrant,
            )
            ModuleCard(
                running = running,
                onZygote = { ask = "zygote" },
                onLsposed = { ask = "lsposed" },
                onModules = onModules,
            )
            DeviceInfoCard(rows = rows)
            OutputCard(
                title = "运行日志",
                icon = Icons.Filled.Info,
                body = log.ifBlank { "暂无日志输出" },
                maxHeight = 320.dp,
                action = {
                    TextButton(onClick = onClearLog, enabled = log.isNotBlank() && !running) {
                        Icon(
                            Icons.Filled.Clear,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.width(4.dp))
                        Text("清空")
                    }
                },
            )
        }

        ask?.let { kind ->
            val zygote = kind == "zygote"
            AlertDialog(
                onDismissRequest = { ask = null },
                title = { Text(if (zygote) "重启 zygote？" else "一键引导 LSPosed？") },
                text = {
                    Text(
                        if (zygote) {
                            "将会结束当前所有应用进程!是否确认"

                        } else {
                            "合并模块 → 启动 zygiskd → 启动 lspd → 热重启 zygote"
                        },
                    )
                },
                confirmButton = {
                    TextButton(onClick = {
                        ask = null
                        if (zygote) onZygote() else onLsposed()
                    }) { Text("继续") }
                },
                dismissButton = {
                    TextButton(onClick = { ask = null }) { Text("取消") }
                },
            )
        }

        if (showRootGuide) {
            AlertDialog(
                onDismissRequest = onDismissRootGuide,
                title = { Text("没有 root 权限") },
                text = {
                    Text(
                        "操作需要root。请到KSU管理器给予Shell或Kagerou Root权限再重启App继续"
                    )
                },
                confirmButton = {
                    TextButton(onClick = onRootGuideManager) { Text("打开 KSU") }
                },
                dismissButton = {
                    TextButton(onClick = onDismissRootGuide) { Text("知道了") }
                },
            )
        }
    }
}

@Composable
private fun PersistentPartitionWarning() {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
    ) {
        Row(modifier = Modifier.padding(16.dp)) {
            Icon(Icons.Filled.Warning, contentDescription = null, modifier = Modifier.size(24.dp))
            Spacer(Modifier.width(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    "警告",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    "此设备未解锁,修改分区将导致无法启动,且无法修复(换个U 9008刷吧)",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    "执行期间请保持APP位于前台, 内核panic可能会掉到EDL, 请手动强制重启",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun StatusCard(phase: BootPhase, status: String, ticker: List<String>) {
    val container: Color
    val content: Color
    val icon: ImageVector
    when (phase) {
        BootPhase.RUNNING -> {
            container = MaterialTheme.colorScheme.secondaryContainer
            content = MaterialTheme.colorScheme.onSecondaryContainer
            icon = Icons.Filled.Refresh
        }

        BootPhase.SUCCESS -> {
            container = MaterialTheme.colorScheme.primaryContainer
            content = MaterialTheme.colorScheme.onPrimaryContainer
            icon = Icons.Filled.CheckCircle
        }

        BootPhase.FAILURE -> {
            container = MaterialTheme.colorScheme.errorContainer
            content = MaterialTheme.colorScheme.onErrorContainer
            icon = Icons.Filled.Warning
        }

        BootPhase.IDLE -> {
            container = MaterialTheme.colorScheme.surfaceContainerHigh
            content = MaterialTheme.colorScheme.onSurfaceVariant
            icon = Icons.Filled.Info
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = container, contentColor = content),
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (phase == BootPhase.RUNNING) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    strokeWidth = 2.5.dp,
                    color = content,
                )
            } else {
                Icon(icon, contentDescription = null, modifier = Modifier.size(24.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    "当前状态",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Medium,
                )
                if (phase == BootPhase.RUNNING && ticker.isNotEmpty()) {
                    // One line slides up every time a new step is logged.
                    AnimatedContent(
                        targetState = ticker,
                        transitionSpec = {
                            (slideInVertically { height -> height } + fadeIn()) togetherWith
                                    (slideOutVertically { height -> -height } + fadeOut())
                        },
                        label = "status-ticker",
                    ) { lines ->
                        Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
                            lines.forEach { line ->
                                Text(
                                    line,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }
                } else {
                    Text(status, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun Actions(
    running: Boolean,
    needsShizukuGrant: Boolean,
    showShizuku: Boolean,
    onStart: () -> Unit,
    onManager: () -> Unit,
    onSelfCheck: () -> Unit,
    onShizuku: () -> Unit,
    onGrant: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Button(
            onClick = onStart,
            enabled = !running,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            Text(
                if (running) "正在执行…" else "获取临时 Root",
                style = MaterialTheme.typography.titleSmall,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            FilledTonalButton(
                onClick = onManager,
                enabled = !running,
                modifier = Modifier
                    .weight(1f)
                    .height(48.dp),
            ) {
                Icon(Icons.Filled.Build, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("打开KSU")
            }
            OutlinedButton(
                onClick = onSelfCheck,
                enabled = !running,
                modifier = Modifier
                    .weight(1f)
                    .height(48.dp),
            ) {
                Text("检查环境")
            }
        }
        if (needsShizukuGrant) {
            OutlinedButton(
                onClick = onGrant,
                enabled = !running,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
            ) {
                Text("允许本应用使用 Shizuku")
            }
        }
        if (showShizuku) {
            FilledTonalButton(
                onClick = onShizuku,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("打开Shizuku")
            }
        }
    }
}

@Composable
private fun ModuleCard(
    running: Boolean,
    onZygote: () -> Unit,
    onLsposed: () -> Unit,
    onModules: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SectionHeader(icon = Icons.Filled.Build, title = "模块")
            Text(
                "因无法使用late-load所以需要手动装载模块与卸载",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                FilledTonalButton(
                    onClick = onZygote,
                    enabled = !running,
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp),
                ) {
                    Text("重启 zygote", maxLines = 1)
                }
                FilledTonalButton(
                    onClick = onLsposed,
                    enabled = !running,
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp),
                ) {
                    Text("引导 LSPosed", maxLines = 1)
                }
            }
            OutlinedButton(
                onClick = onModules,
                enabled = !running,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(44.dp),
            ) {
                Text("模块管理", maxLines = 1)
            }
        }
    }
}

@Composable
private fun DeviceInfoCard(rows: List<Pair<String, String>>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SectionHeader(icon = Icons.Filled.Info, title = "设备信息")
            rows.forEachIndexed { index, (label, value) ->
                if (index > 0) {
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                }
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        label,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    SelectionContainer {
                        Text(
                            value,
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun OutputCard(
    title: String,
    icon: ImageVector,
    body: String,
    maxHeight: Dp,
    action: @Composable (() -> Unit)? = null,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SectionHeader(icon = icon, title = title, modifier = Modifier.weight(1f))
                action?.invoke()
            }
            val scroll = rememberScrollState()
            LaunchedEffect(body) {
                if (scroll.maxValue > 0) {
                    scroll.scrollTo(scroll.maxValue)
                }
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = maxHeight),
            ) {
                SelectionContainer {
                    Text(
                        text = body,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 18.sp,
                        modifier = Modifier.verticalScroll(scroll),
                    )
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(icon: ImageVector, title: String, modifier: Modifier = Modifier) {
    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Icon(
            icon,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.width(8.dp))
        Text(
            title,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
