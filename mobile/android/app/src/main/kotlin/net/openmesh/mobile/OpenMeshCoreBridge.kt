package net.openmesh.mobile

import android.content.Context

class OpenMeshCoreBridge(
    context: Context,
) {
    private val dataDir: String = context.filesDir.resolve("openmesh").absolutePath
    private var engine: Any? = null

    init {
        configureBootstrapManifestURLs(BuildConfig.OPENMESH_BOOTSTRAP_MANIFEST_URLS)
    }

    fun configure(mode: String, hops: Int, bandwidthMbps: Int) {
        invokeEngine("configure", "Configure", mode, hops, bandwidthMbps)
    }

    fun attachTun(fd: Int) {
        invokeEngine("attachTun", "AttachTun", fd)
    }

    fun start() {
        invokeEngine("start", "Start")
    }

    fun stop() {
        invokeEngine("stop", "Stop")
    }

    fun setRelaySuspended(suspended: Boolean) {
        invokeEngine("setRelaySuspended", "SetRelaySuspended", suspended)
    }

    fun statusJson(): String {
        return invokeEngineWithResult<String>("statusJSON", "StatusJSON") ?: "{}"
    }

    fun bytesIn(): Long {
        return (invokeEngineWithResult<Number>("bytesIn", "BytesIn") ?: 0L).toLong()
    }

    fun bytesOut(): Long {
        return (invokeEngineWithResult<Number>("bytesOut", "BytesOut") ?: 0L).toLong()
    }

    fun isRunning(): Boolean {
        return invokeEngineWithResult<Boolean>("isRunning", "IsRunning") ?: false
    }

    private fun configureBootstrapManifestURLs(raw: String) {
        if (raw.isBlank()) {
            return
        }
        invokeEngine("setBootstrapManifestURLs", "SetBootstrapManifestURLs", raw)
    }

    private fun invokeEngine(vararg methodNames: String, args: Any?) {
        val instance = ensureEngine()
        val method = instance.javaClass.methods.firstOrNull { candidate ->
            methodNames.any { it == candidate.name } && candidate.parameterTypes.size == args.size
        } ?: throw IllegalStateException("Missing engine method: ${methodNames.joinToString("/")}")
        method.invoke(instance, *args)
    }

    private fun <T> invokeEngineWithResult(vararg methodNames: String): T? {
        val instance = ensureEngine()
        val method = instance.javaClass.methods.firstOrNull { candidate ->
            methodNames.any { it == candidate.name } && candidate.parameterTypes.isEmpty()
        } ?: throw IllegalStateException("Missing engine result method: ${methodNames.joinToString("/")}")
        @Suppress("UNCHECKED_CAST")
        return method.invoke(instance) as? T
    }

    private fun ensureEngine(): Any {
        val current = engine
        if (current != null) {
            return current
        }

        val bindingClass = Class.forName(BINDING_CLASS_NAME)
        val factory = bindingClass.methods.firstOrNull { candidate ->
            candidate.parameterTypes.contentEquals(arrayOf(String::class.java)) &&
                (candidate.name == "newEngine" || candidate.name == "NewEngine")
        } ?: throw IllegalStateException("Unable to locate gomobile Engine factory in $BINDING_CLASS_NAME")

        val created = factory.invoke(null, dataDir)
            ?: throw IllegalStateException("gomobile Engine factory returned null")
        engine = created
        return created
    }

    companion object {
        private const val BINDING_CLASS_NAME = "go.openmeshmobile.Openmeshmobile"
    }
}
