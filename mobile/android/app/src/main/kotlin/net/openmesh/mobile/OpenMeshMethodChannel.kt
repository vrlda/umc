package net.openmesh.mobile

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

class OpenMeshMethodChannel(
    private val activity: Activity,
) : MethodChannel.MethodCallHandler {
    private lateinit var channel: MethodChannel

    fun configure(flutterEngine: FlutterEngine) {
        channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "prepareVpn" -> result.success(prepareVpn())
            "start" -> handleStart(call, result)
            "stop" -> {
                OpenMeshVpnService.stop(activity)
                result.success(OpenMeshVpnService.snapshot())
            }
            "status" -> result.success(OpenMeshVpnService.snapshot())
            else -> result.notImplemented()
        }
    }

    private fun prepareVpn(): Boolean {
        val intent = VpnService.prepare(activity) ?: return true
        activity.startActivity(intent)
        return false
    }

    private fun handleStart(call: MethodCall, result: MethodChannel.Result) {
        if (VpnService.prepare(activity) != null) {
            result.error("vpn_permission_required", "VPN permission has not been granted yet.", null)
            return
        }

        val hops = (call.argument<Int>("hops") ?: DEFAULT_HOPS).coerceIn(1, 3)
        val mode = (call.argument<String>("mode") ?: DEFAULT_MODE).lowercase()
        val bandwidthMbps = (call.argument<Int>("bandwidthMbps") ?: DEFAULT_BANDWIDTH_MBPS).coerceAtLeast(0)

        val intent = Intent(activity, OpenMeshVpnService::class.java).apply {
            action = OpenMeshVpnService.ACTION_START
            putExtra(OpenMeshVpnService.EXTRA_HOPS, hops)
            putExtra(OpenMeshVpnService.EXTRA_MODE, mode)
            putExtra(OpenMeshVpnService.EXTRA_BANDWIDTH_MBPS, bandwidthMbps)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            activity.startForegroundService(intent)
        } else {
            activity.startService(intent)
        }
        result.success(OpenMeshVpnService.snapshot())
    }

    companion object {
        const val CHANNEL_NAME = "openmesh/vpn"

        private const val DEFAULT_HOPS = 2
        private const val DEFAULT_MODE = "off"
        private const val DEFAULT_BANDWIDTH_MBPS = 10
    }
}
