package net.openmesh.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.BatteryManager
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

class OpenMeshVpnService : VpnService() {
    private lateinit var coreBridge: OpenMeshCoreBridge

    private var vpnInterface: ParcelFileDescriptor? = null
    private var currentMode: String = DEFAULT_MODE
    private var currentHops: Int = DEFAULT_HOPS
    private var currentBandwidthMbps: Int = DEFAULT_BANDWIDTH_MBPS
    private var statsExecutor: ScheduledExecutorService? = null

    override fun onCreate() {
        super.onCreate()
        coreBridge = OpenMeshCoreBridge(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn()
            ACTION_START -> startVpn(intent)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun startVpn(intent: Intent) {
        currentMode = (intent.getStringExtra(EXTRA_MODE) ?: DEFAULT_MODE).lowercase()
        currentHops = intent.getIntExtra(EXTRA_HOPS, DEFAULT_HOPS).coerceIn(1, 3)
        currentBandwidthMbps = intent.getIntExtra(EXTRA_BANDWIDTH_MBPS, DEFAULT_BANDWIDTH_MBPS).coerceAtLeast(0)

        if (vpnInterface == null) {
            vpnInterface = Builder()
                .setSession(getString(R.string.openmesh_notification_title))
                .setMtu(1500)
                .addAddress("100.64.0.2", 30)
                .addDnsServer("1.1.1.1")
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .establish()
        }

        val tunnelFd = vpnInterface?.fd
            ?: throw IllegalStateException("VpnService.Builder.establish() returned null")

        ensureNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        coreBridge.configure(currentMode, currentHops, currentBandwidthMbps)
        coreBridge.attachTun(tunnelFd)
        coreBridge.setRelaySuspended(shouldSuspendRelay())
        coreBridge.start()

        running = true
        relaySuspended = shouldSuspendRelay()
        startStatsLoop()
        refreshSnapshot()
    }

    private fun stopVpn() {
        statsExecutor?.shutdownNow()
        statsExecutor = null

        kotlin.runCatching { coreBridge.stop() }
        kotlin.runCatching { vpnInterface?.close() }
        vpnInterface = null

        running = false
        relaySuspended = false
        bytesIn = 0
        bytesOut = 0
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun startStatsLoop() {
        statsExecutor?.shutdownNow()
        statsExecutor = Executors.newSingleThreadScheduledExecutor().also { executor ->
            executor.scheduleAtFixedRate(
                { refreshSnapshot() },
                0,
                1,
                TimeUnit.SECONDS,
            )
        }
    }

    private fun refreshSnapshot() {
        bytesIn = coreBridge.bytesIn()
        bytesOut = coreBridge.bytesOut()
        relaySuspended = shouldSuspendRelay()
        kotlin.runCatching { coreBridge.setRelaySuspended(relaySuspended) }

        statusJson = kotlin.runCatching { coreBridge.statusJson() }.getOrDefault("{}")
    }

    private fun shouldSuspendRelay(): Boolean {
        if (currentMode != "relay" && currentMode != "exit") {
            return false
        }

        val batteryIntent = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: return false
        val level = batteryIntent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = batteryIntent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        if (level < 0 || scale <= 0) {
            return false
        }
        val percentage = (level * 100) / scale
        return percentage < 20
    }

    private fun buildNotification(): Notification {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or immutableFlag(),
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_openmesh)
            .setContentTitle(getString(R.string.openmesh_notification_title))
            .setContentText(getString(R.string.openmesh_notification_text))
            .setOngoing(true)
            .setSilent(true)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            getString(R.string.openmesh_notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.openmesh_notification_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    companion object {
        const val ACTION_START = "net.openmesh.mobile.action.START"
        const val ACTION_STOP = "net.openmesh.mobile.action.STOP"
        const val EXTRA_HOPS = "net.openmesh.mobile.extra.HOPS"
        const val EXTRA_MODE = "net.openmesh.mobile.extra.MODE"
        const val EXTRA_BANDWIDTH_MBPS = "net.openmesh.mobile.extra.BANDWIDTH_MBPS"

        private const val DEFAULT_HOPS = 2
        private const val DEFAULT_MODE = "off"
        private const val DEFAULT_BANDWIDTH_MBPS = 10
        private const val NOTIFICATION_CHANNEL_ID = "openmesh_vpn"
        private const val NOTIFICATION_ID = 1042

        @Volatile
        private var running: Boolean = false

        @Volatile
        private var relaySuspended: Boolean = false

        @Volatile
        private var bytesIn: Long = 0

        @Volatile
        private var bytesOut: Long = 0

        @Volatile
        private var statusJson: String = "{}"

        fun stop(context: Context) {
            val intent = Intent(context, OpenMeshVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }

        fun snapshot(): Map<String, Any?> {
            val status = kotlin.runCatching { JSONObject(statusJson) }.getOrNull()
            return mapOf(
                "running" to running,
                "relaySuspended" to relaySuspended,
                "bytesIn" to bytesIn,
                "bytesOut" to bytesOut,
                "statusJson" to statusJson,
                "nodeId" to status?.optString("node_id", ""),
                "mode" to status?.optString("mode", DEFAULT_MODE),
                "hops" to status?.optInt("hops", DEFAULT_HOPS),
            )
        }

        private fun immutableFlag(): Int {
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_IMMUTABLE
            } else {
                0
            }
        }
    }
}
