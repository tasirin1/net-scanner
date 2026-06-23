package com.example.networkscanner

import android.text.method.LinkMovementMethod
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.TextView
import com.google.android.material.button.MaterialButton
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.URL
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

class MainActivity : AppCompatActivity() {

    private lateinit var inputTarget: android.widget.EditText
    private lateinit var statusText: TextView
    private lateinit var statusDot: View
    private lateinit var tvResults: TextView
    private lateinit var tvSummary: TextView
    private lateinit var cardResults: View
    private lateinit var progressBar: android.widget.ProgressBar
    private lateinit var tvProgress: TextView
    private lateinit var inputMaxHosts: android.widget.EditText
    private lateinit var inputTimeout: android.widget.EditText
    @Volatile
    private var isScanning = false
    private val ui = Handler(Looper.getMainLooper())

    private val quickPorts = intArrayOf(80, 443, 8080, 8443, 22, 23, 8291, 2000, 21, 53, 3389, 3306, 8081, 8000, 3000, 5000, 8888, 9000, 81, 444, 5555, 5900, 6379, 27017, 7547, 6666)

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(R.layout.activity_main)

        inputTarget = findViewById(R.id.inputTarget)
        statusText = findViewById(R.id.tvStatus)
        statusDot = findViewById(R.id.dotStatus)
        tvResults = findViewById(R.id.tvResults)
        tvSummary = findViewById(R.id.tvSummary)
        cardResults = findViewById(R.id.cardResults)
        progressBar = findViewById(R.id.progressBar)
        tvProgress = findViewById(R.id.tvProgress)
        inputMaxHosts = findViewById(R.id.inputMaxHosts)
        inputTimeout = findViewById(R.id.inputTimeout)

        findViewById<MaterialButton>(R.id.btnQuick).setOnClickListener { quickScan() }
        findViewById<MaterialButton>(R.id.btnFull).setOnClickListener { fullScan() }
        findViewById<MaterialButton>(R.id.btnDiscover).setOnClickListener { discoverScan() }

    }

    // ─── Settings helpers ───
    private fun getMaxHosts(): Int {
        val t = inputMaxHosts.text?.toString()?.trim() ?: ""
        return t.toIntOrNull()?.coerceIn(1, 65535) ?: 254
    }

    private fun getTimeout(): Int {
        val t = inputTimeout.text?.toString()?.trim() ?: ""
        return t.toIntOrNull()?.coerceIn(50, 5000) ?: 300
    }

    // ─── Progress helpers ───
    private fun showProgress() {
        progressBar.visibility = View.VISIBLE
        progressBar.progress = 0
        tvProgress.visibility = View.VISIBLE
        tvProgress.text = ""
    }

    private fun hideProgress() {
        progressBar.visibility = View.GONE
        tvProgress.visibility = View.GONE
    }

    private fun updateProgress(done: Int, total: Int) {
        if (total > 0) {
            val pct = (done * 100) / total
            progressBar.progress = pct
            progressBar.max = 100
            tvProgress.text = "$done / $total hosts"
        }
    }

    // ─── Get target from input ───
    private fun getTarget(): String {
        return inputTarget.text?.toString()?.trim() ?: ""
    }

    // ─── Quick scan ───
    private fun quickScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        if (target.isEmpty()) { toast("Enter target!"); return }
        runScan(target, quickPorts, "Quick Scan")
    }

    // ─── Full scan (all ports on a single target) ───
    private fun fullScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        if (target.isEmpty()) { toast("Enter target!"); return }
        AlertDialog.Builder(this)
            .setTitle("Full Scan")
            .setMessage("Scans 200+ ports on ALL hosts in subnet (auto-expands single IP to /24).\nMay take 2-3 minutes.")
            .setPositiveButton("Start") { _, _ -> runScan(target, getAllPorts(), "Full Scan") }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ─── Nmap-style scan (OS detection + version + aggressive) ───
    private fun nmapScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        if (target.isEmpty()) { toast("Enter target!"); return }
        val nmapPath = findNmapBinary()
        if (nmapPath != null) {
            AlertDialog.Builder(this)
                .setTitle("Nmap Scan")
                .setMessage("Real Nmap found!\nRunning: $nmapPath\n\nMode: -A (OS, version, scripts, traceroute)\nPorts: top 1000\n\nMay take 1-3 minutes.")
                .setPositiveButton("Start") { _, _ -> runRealNmap(target, nmapPath) }
                .setNegativeButton("Cancel", null)
                .show()
        } else {
            AlertDialog.Builder(this)
                .setTitle("Nmap Not Found")
                .setMessage("Nmap binary not installed.\n\nTo use real Nmap, install Termux and run:\npkg install nmap\n\nUsing built-in scanner instead.")
                .setPositiveButton("Use Built-in") { _, _ -> runScan(target, getAllPorts(), "Nmap-Style") }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    // ─── Find Nmap binary ───
    private fun findNmapBinary(): String? {
        val paths = listOf(
            "/data/data/com.termux/files/usr/bin/nmap",
            "/system/bin/nmap",
            "/system/xbin/nmap",
            "/data/local/bin/nmap",
            "/data/local/nmap",
            "/sbin/nmap",
            "/su/bin/nmap"
        )
        for (path in paths) {
            try {
                val f = java.io.File(path)
                if (f.exists() && f.canExecute()) return path
            } catch (_: Exception) { }
        }
        try {
            val envPath = System.getenv("PATH") ?: return null
            for (dir in envPath.split(":")) {
                try {
                    val f = java.io.File(dir, "nmap")
                    if (f.exists() && f.canExecute()) return f.absolutePath
                } catch (_: Exception) { }
            }
        } catch (_: Exception) { }
        return null
    }

    // ─── Run real Nmap and parse XML output ───
    private fun runRealNmap(target: String, nmapPath: String) {
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Starting real Nmap...\n"
        tvSummary.text = ""
        status("Nmap running...", "#E65100", true)
        showProgress()
        tvProgress.text = "Scanning..."

        Thread {
            val allResults = ConcurrentHashMap<String, MutableList<String>>()
            val osDetected = ConcurrentHashMap<String, String>()
            val startTime = System.currentTimeMillis()

            try {
                val cmd = arrayOf(
                    nmapPath,
                    "-A",
                    "-T4",
                    "--top-ports", "1000",
                    "-oX", "-",
                    "--unprivileged",
                    target
                )
                status("Executing: nmap -A $target", "#E65100", true)

                val process = Runtime.getRuntime().exec(cmd)
                val reader = BufferedReader(InputStreamReader(process.inputStream, "UTF-8"))
                val errorReader = BufferedReader(InputStreamReader(process.errorStream, "UTF-8"))

                val xmlBuilder = StringBuilder()
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    xmlBuilder.append(line).append('\n')
                }
                reader.close()

                val errBuilder = StringBuilder()
                while (errorReader.readLine().also { line = it } != null) {
                    errBuilder.append(line).append('\n')
                }
                errorReader.close()

                val exitCode = process.waitFor()
                val xml = xmlBuilder.toString()

                if (exitCode != 0 && xml.isEmpty()) {
                    uiPost("Nmap error: ${errBuilder.toString().take(200)}", "#C62828", false)
                    isScanning = false
                    return@Thread
                }

                parseNmapXml(xml, allResults, osDetected)

            } catch (e: Exception) {
                uiPost("Nmap error: ${e.message?.take(100) ?: "Unknown"}", "#C62828", false)
                isScanning = false
                return@Thread
            }

            val elapsed = System.currentTimeMillis() - startTime
            if (allResults.isNotEmpty()) {
                ui.post {
                    updateResults(allResults, osDetected)
                    status("${allResults.size} host(s) found in ${elapsed / 1000}s", "#2E7D32", true)
                    toast("Nmap complete: ${allResults.size} hosts")
                }
            } else {
                uiPost("No hosts found", "#C62828", false)
            }
            hideProgress()
            isScanning = false
        }.start()
    }

    // ─── Parse Nmap XML output ───
    private fun parseNmapXml(xml: String, results: ConcurrentHashMap<String, MutableList<String>>, osDetected: ConcurrentHashMap<String, String>) {
        try {
            val hostBlocks = xml.split("</host>")
            for (block in hostBlocks) {
                if (!block.contains("<address")) continue

                var ip = ""
                var hostname = ""
                val services = mutableListOf<String>()

                // Extract IP - simple addr pattern
                val ipStart = block.indexOf("addr=\"")
                if (ipStart >= 0) {
                    val ipEnd = block.indexOf("\"", ipStart + 6)
                    if (ipEnd >= 0) {
                        val candidate = block.substring(ipStart + 6, ipEnd)
                        if (candidate.count { it == '.' } == 3) ip = candidate
                    }
                }

                // Extract hostname
                val hnIdx = block.indexOf("name=\"")
                val hnEnd = if (hnIdx >= 0) block.indexOf("\"", hnIdx + 6) else -1
                if (hnIdx >= 0 && hnEnd >= 0) {
                    val hn = block.substring(hnIdx + 6, hnEnd)
                    if (hn.contains(".") && !hn.contains(":")) hostname = hn
                }

                // Extract OS
                val osIdx = block.indexOf("osmatch")
                if (osIdx >= 0) {
                    val osNameIdx = block.indexOf("name=\"", osIdx)
                    if (osNameIdx >= 0) {
                        val osEnd = block.indexOf("\"", osNameIdx + 6)
                        if (osEnd >= 0) {
                            val os = block.substring(osNameIdx + 6, osEnd).take(30)
                            if (os.isNotEmpty()) osDetected[ip] = os
                        }
                    }
                }

                if (ip.isEmpty()) continue

                // Parse ports
                var searchFrom = 0
                while (true) {
                    val portTag = block.indexOf("<port ", searchFrom)
                    if (portTag < 0) break

                    // Get portid
                    val pidIdx = block.indexOf("portid=\"", portTag)
                    if (pidIdx < 0) { searchFrom = portTag + 1; continue }
                    val pidEnd = block.indexOf("\"", pidIdx + 8)
                    if (pidEnd < 0) { searchFrom = portTag + 1; continue }
                    val portStr = block.substring(pidIdx + 8, pidEnd)
                    if (portStr.toIntOrNull() == null) { searchFrom = portTag + 1; continue }
                    val port = portStr.toIntOrNull()!!

                    // Get state
                    val stateIdx = block.indexOf("state=\"", portTag)
                    val stateEnd = if (stateIdx >= 0) block.indexOf("\"", stateIdx + 7) else -1
                    val state = if (stateIdx >= 0 && stateEnd >= 0) block.substring(stateIdx + 7, stateEnd) else ""

                    searchFrom = portTag + 1
                    if (state != "open") continue

                    // Get service name
                    val svcIdx = block.indexOf("name=\"", portTag)
                    val svcEnd = if (svcIdx >= 0) block.indexOf("\"", svcIdx + 6) else -1
                    val svcName = if (svcIdx >= 0 && svcEnd >= 0) block.substring(svcIdx + 6, svcEnd) else "unknown"

                    // Get product/version
                    val prodIdx = block.indexOf("product=\"", portTag)
                    val prodEnd = if (prodIdx >= 0) block.indexOf("\"", prodIdx + 9) else -1
                    val product = if (prodIdx >= 0 && prodEnd >= 0) block.substring(prodIdx + 9, prodEnd).take(30) else ""

                    val verIdx = block.indexOf("version=\"", portTag)
                    val verEnd = if (verIdx >= 0) block.indexOf("\"", verIdx + 9) else -1
                    val version = if (verIdx >= 0 && verEnd >= 0) block.substring(verIdx + 9, verEnd).take(20) else ""

                    val detail = buildString {
                        append("Port $port ($svcName)")
                        if (product.isNotEmpty()) append(" - $product")
                        if (version.isNotEmpty()) append(" $version")
                    }
                    services.add(detail)
                }

                if (services.isNotEmpty()) {
                    if (hostname.isNotEmpty()) {
                        services.add(0, "\\u2192 $hostname")
                    }
                    results[ip] = services
                }
            }
        } catch (e: Exception) {
            uiPost("Parse error: ${e.message?.take(50)}", "#C62828", false)
        }
    }

    // ─── Core scan engine ───
    private fun runScan(target: String, ports: IntArray, mode: String) {
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Initializing $mode...\n"
        tvSummary.text = ""
        status("Preparing $mode...", "#E65100", true)
        showProgress()

        Thread {
            val startTime = System.currentTimeMillis()
            val allResults = ConcurrentHashMap<String, MutableList<String>>()
            val activeHosts = AtomicInteger(0)
            val osDetected = ConcurrentHashMap<String, String>()
            val scanCount = AtomicInteger(0)

            try {
                if (target.isEmpty()) { uiPost("Empty target", "#C62828", false); isScanning = false; return@Thread }
                // Parse target into list of IPs
                val targets = autoExpandTarget(target)
                if (targets.isEmpty()) {
                    uiPost("Invalid target: $target", "#C62828", false)
                    isScanning = false
                    return@Thread
                }
                uiPost("$mode: ${targets.size} host(s) to scan", "#E65100", true)

                // Find gateway for local subnet
                val localIp = getWifiIp()
                val isLocal = target.contains(localIp.substringBeforeLast("."))

                // ARP/ping discovery only for local subnet
                var liveIps = targets.toSet()
                if (isLocal && targets.size > 1) {
                    uiPost("ARP discovery...", "#E65100", true)
                    val live = arpScan(targets.first().substringBeforeLast(".") + ".")
                    liveIps = targets.filter { it in live }.toSet()
                    if (liveIps.isEmpty()) liveIps = targets.take(10).toSet()
                }

                val scanTargets = liveIps.toList()
                uiPost("Scanning ${scanTargets.size} host(s)...", "#E65100", true)

                val portTimeout = getTimeout()
                val latch = CountDownLatch(scanTargets.size)
                val scannerPool = Executors.newFixedThreadPool(Math.min(30, scanTargets.size))

                for (ip in scanTargets) {
                    if (!isScanning) { latch.countDown(); continue }
                    scannerPool.execute {
                        try {
                            if (!isScanning) return@execute
                            val ipServices = mutableListOf<String>()
                            var hasOs = false

                            // Try to resolve hostname
                            var hostname = ""
                            try {
                                val addr = InetAddress.getByName(ip)
                                val hn = addr.hostName ?: ""
                                if (hn != ip) hostname = hn
                            } catch (_: Exception) { }

                            // Quick ping to measure RTT
                            var rtt = ""
                            try {
                                val start = System.nanoTime()
                                val reachable = InetAddress.getByName(ip).isReachable(500)
                                if (reachable) {
                                    val ms = (System.nanoTime() - start) / 1_000_000
                                    if (ms < 500) rtt = "${ms}ms"
                                }
                            } catch (_: Exception) { }

                            for (port in ports) {
                                if (!isScanning) break
                                try {
                                    val s = Socket()
                                    s.connect(InetSocketAddress(ip, port), if (mode == "Nmap-Style") portTimeout.coerceAtMost(500) else portTimeout)
                                    if (!s.isConnected) { s.close(); continue }
                                    val detail = probeService(ip, port, s, mode)
                                    synchronized(ipServices) { ipServices.add(detail) }
                                    s.close()
                                } catch (_: Exception) { }
                            }

                            if (ipServices.isNotEmpty()) {
                                // Prepend hostname info
                                if (hostname.isNotEmpty()) {
                                    synchronized(ipServices) { ipServices.add(0, "\u2192 $hostname") }
                                }
                                if (rtt.isNotEmpty()) {
                                    synchronized(ipServices) { ipServices.add(if (hostname.isEmpty()) 0 else 1, "\u26A1 $rtt") }
                                }

                                allResults[ip] = ipServices
                                activeHosts.incrementAndGet()

                                // OS fingerprint (only in Nmap mode)
                                if (mode == "Nmap-Style") {
                                    val os = guessOs(ip, ipServices)
                                    if (os.isNotEmpty()) osDetected[ip] = os
                                }

                                ui.post { updateResults(allResults, osDetected) }
                            }
                        } finally {
                                latch.countDown()
                                val done = scanCount.incrementAndGet()
                                ui.post { updateProgress(done, scanTargets.size) }
                            }
                    }
                }

                scannerPool.shutdown()
                latch.await()
                ui.post { updateResults(allResults, osDetected) }

            } catch (e: Exception) {
                uiPost("Error: ${e.message}", "#C62828", false)
            }

            val elapsed = System.currentTimeMillis() - startTime
            val summary = "\n── Done in ${elapsed / 1000}s ──  ${activeHosts.get()} host(s) found"
            ui.post {
                tvSummary.text = summary
                status("${activeHosts.get()} host(s) found in ${elapsed / 1000}s", "#2E7D32", true)
                toast("Complete: ${activeHosts.get()} hosts")
            }
            hideProgress()
            isScanning = false
        }.start()
    }

    // ─── Parse target ───
    private fun expandTarget(target: String): List<String> {
        // Single IP
        val ipRegex = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")
        if (ipRegex.matches(target)) return listOf(target)

        // CIDR /24
        val cidr = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})/(\d{1,2})""").find(target)
        if (cidr != null) {
            val prefix = cidr.groupValues[1]
            val mask = cidr.groupValues[3].toIntOrNull() ?: 24
            if (mask == 24) return (1..254).map { "$prefix.$it" }
            if (mask == 16) {
                val list = mutableListOf<String>()
                for (i in 0..255) for (j in 1..254) list.add("$prefix.$i.$j")
                return list.take(254)
            }
        }

        // Hostname
        try {
            val addrs = InetAddress.getAllByName(target)
            if (addrs.isNotEmpty()) return addrs.map { it.hostAddress ?: target }
        } catch (_: Exception) { }

        return listOf(target)
    }

    // ─── Auto-expand single IP to /24 subnet ───
    private fun autoExpandTarget(target: String): List<String> {
        val ipRegex = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$""")
        if (ipRegex.matches(target)) {
            return (1..254).map { "${target.substringBeforeLast(".")}.$it" }
        }
        // Already a subnet or hostname
        val expanded = expandTarget(target)
        if (expanded.size < 2 && expanded.isNotEmpty()) {
            val ip = expanded.first()
            if (ipRegex.matches(ip)) {
                return (1..254).map { "${ip.substringBeforeLast(".")}.$it" }
            }
        }
        return expanded
    }

    // ─── WiFi IP ───
    private fun getWifiIp(): String {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val ni = interfaces.nextElement()
                if (ni.name.startsWith("wlan") || ni.name.startsWith("eth")) {
                    val addrs = ni.inetAddresses
                    while (addrs.hasMoreElements()) {
                        val addr = addrs.nextElement()
                        val ip = addr.hostAddress ?: continue
                        if (!addr.isLoopbackAddress && ip.contains(".")) return ip
                    }
                }
            }
        } catch (_: Exception) { }
        return try { InetAddress.getLocalHost().hostAddress ?: "192.168.0.101" } catch (_: Exception) { "192.168.0.101" }
    }

    // ─── ARP ping ───
    private fun arpScan(subnet: String): Set<String> {
        val live = Collections.synchronizedSet(mutableSetOf<String>())
        val pool = Executors.newFixedThreadPool(50)
        for (i in 1..254) {
            val ip = "$subnet$i"
            pool.execute {
                try { if (InetAddress.getByName(ip).isReachable(300)) live.add(ip) } catch (_: Exception) { }
            }
        }
        pool.shutdown()
        try { pool.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS) } catch (_: Exception) { }
        return live
    }

    // ─── Probe service ───
    private fun probeService(ip: String, port: Int, sock: Socket, mode: String): String {
        val isWeb = port in intArrayOf(80, 81, 82, 88, 443, 444, 3000, 4000, 5000, 5001, 7000, 7070, 7443, 7547, 8000, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8180, 8222, 8243, 8280, 8443, 8444, 8530, 8531, 8649, 8800, 8834, 8880, 8888, 8889, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9100, 9200, 9290, 9300, 9418, 9443, 9600, 9800, 9999, 10000, 10001, 10080, 12345, 13337, 16010, 16379, 17000, 17001, 20000, 22000, 25565, 32400, 32764, 49154, 49155, 49156, 50000, 50100, 50200, 61616, 64738, 65535)

        return if (isWeb) probeHttp(ip, port, mode) else probeTcp(ip, port, sock, mode)
    }

    private val webPaths = listOf(
        "/", "/index.htm", "/index.html", "/index.php", "/login.htm", "/login.html", "/login.php",
        "/login", "/admin.htm", "/admin.html", "/admin", "/admin/", "/admin/index.htm",
        "/status", "/status.htm", "/status.html", "/status.asp",
        "/config", "/config.htm", "/config.html", "/config.asp",
        "/setup", "/setup.htm", "/setup.html", "/setup.asp",
        "/manager", "/manager.htm", "/manager.html", "/manager.asp",
        "/cgi-bin/", "/cgi-bin/login", "/cgi-bin/status",
        "/backup", "/backup.htm", "/backup.html",
        "/wps", "/wps.htm", "/upnp", "/upnp.xml",
        "/dlf", "/HNAP", "/HNAP1", "/goform", "/goform/",
        "/startup.htm", "/startup.asp",
        "/WAN.htm", "/WAN.asp", "/LAN.htm", "/LAN.asp",
        "/WIFI.htm", "/WIFI.asp", "/wireless.htm",
        "/dhcp.htm", "/dhcp.asp", "/static.htm",
        "/password.htm", "/password.asp",
        "/user.htm", "/user.asp", "/users.htm",
        "/system.htm", "/system.asp", "/info.htm", "/info.asp",
        "/reboot", "/reboot.htm", "/reboot.asp", "/restart",
        "/upgrade", "/upgrade.htm", "/upgrade.asp",
        "/log", "/log.htm", "/log.asp", "/logs.htm",
        "/error.htm", "/404.htm", "/test.htm",
        "/shell", "/cmd", "/command", "/exec",
        "/debug", "/debug.htm", "/debug.asp",
        "/telnet", "/ssh", "/vnc",
        "/proxy", "/proxy.htm",
        "/favicon.ico", "/robots.txt", "/sitemap.xml",
        "/.env", "/config.json", "/config.xml", "/config.txt",
        "/webconfig", "/web.xml", "/WEB-INF/web.xml"
    )

    // ─── HTTP probe ───
    private fun probeHttp(ip: String, port: Int, mode: String): String {
        try {
            val protocol = if (port == 443 || port == 8443 || port == 7443 || port == 8243 || port == 9443 || port == 4443 || port == 4343 || port == 444 || port == 8531 || port == 8444) "https" else "http"
            val base = "$protocol://$ip:$port"

            // First check root
            val rootResult = checkHttpPath(base, "/", mode)
            if (rootResult == null) return "Port $port (${guessService(port)}) [TCP open]"

            // Then probe common paths (limited to save time)
            val foundPaths = mutableListOf<String>()
            val pathsToProbe = if (mode == "Nmap-Style") webPaths else webPaths.take(30)

            for (path in pathsToProbe) {
                if (path == "/") continue
                val result = checkHttpPath(base, path, mode)
                if (result != null) foundPaths.add(result)
                if (foundPaths.size >= 15) break  // cap at 15 found paths
            }

            val parts = mutableListOf<String>()
            parts.add("Port $port (${guessService(port)})")
            if (rootResult.isNotEmpty()) parts.add(rootResult)
            if (foundPaths.isNotEmpty()) {
                parts.add("| Paths:")
                foundPaths.forEach { parts.add("  \u2514 $it") }
            }
            return parts.joinToString("\n")
        } catch (_: Exception) {
            return "Port $port (${guessService(port)}) [TCP open]"
        }
    }

    private fun checkHttpPath(base: String, path: String, mode: String): String? {
        return try {
            val conn = URL("$base$path").openConnection() as HttpURLConnection
            conn.connectTimeout = if (mode == "Nmap-Style") 1500 else 800
            conn.readTimeout = 1000
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 NetScan/1.1")
            conn.setRequestProperty("Accept", "text/html,*/*")

            val code = try { conn.responseCode } catch (_: Exception) { 0 }
            if (code == 0 || code == 404 || code == 410) { conn.disconnect(); return null }

            val msg = try { conn.responseMessage } catch (_: Exception) { "" }
            val loc = conn.getHeaderField("Location") ?: ""
            val ct = conn.getHeaderField("Content-Type") ?: ""
            val www = conn.getHeaderField("WWW-Authenticate") ?: ""

            // Get page title or size indication
            var title = ""
            var size = 0
            try {
                val stream = if (code in 200..399) conn.inputStream else conn.errorStream
                val reader = BufferedReader(InputStreamReader(stream, "UTF-8"), 512)
                var line: String?
                var found = false
                while (reader.readLine().also { line = it } != null) {
                    size += (line?.length ?: 0) + 1
                    if (!found) {
                        val m = Regex("<title[^>]*>(.*?)</title>", RegexOption.IGNORE_CASE).find(line ?: "")
                        if (m != null) { title = m.groupValues[1].take(50).trim(); found = true }
                    }
                    if (found && size > 2048) break
                }
                reader.close()
            } catch (_: Exception) { }

            conn.disconnect()

            val info = mutableListOf<String>()
            info.add("$path")
            info.add("HTTP $code${if (msg.isNotEmpty()) " $msg" else ""}")
            if (title.isNotEmpty()) info.add("\"$title\"")
            if (www.isNotEmpty()) info.add("Auth")
            if (loc.isNotEmpty() && loc.length < 60) info.add("-> $loc")
            if (path != "/") {
                val sizeKb = size / 1024
                if (sizeKb > 0) info.add("[${sizeKb}KB]")
            }
            return info.joinToString(" ")
        } catch (_: Exception) { null }
    }

    // ─── TCP banner grab ───
    private fun probeTcp(ip: String, port: Int, sock: Socket, mode: String): String {
        var banner = ""
        try {
            sock.soTimeout = if (mode == "Nmap-Style") 1500 else 800
            val reader = BufferedReader(InputStreamReader(sock.getInputStream(), "ISO-8859-1"))
            val cbuf = CharArray(512)
            val len = reader.read(cbuf)
            if (len > 0) banner = String(cbuf, 0, len).trim().replace(Regex("[\\r\\n]+"), " · ").take(60)
            reader.close()
        } catch (_: Exception) { }
        return if (banner.isNotEmpty()) "Port $port (${guessService(port)}) → \"$banner\""
        else "Port $port (${guessService(port)}) [open]"
    }

    // ─── OS fingerprint ───
    private fun guessOs(ip: String, services: List<String>): String {
        val all = services.joinToString(" ")
        return when {
            all.contains("GoAhead") -> "Router (Tenda/GoAhead)"
            all.contains("RouterOS") || all.contains("routeros") -> "MikroTik RouterOS"
            all.contains("Winbox") || all.contains("8291") -> "MikroTik RouterOS"
            all.contains("Apache") && all.contains("Ubuntu") -> "Linux (Ubuntu + Apache)"
            all.contains("Apache") && all.contains("Debian") -> "Linux (Debian + Apache)"
            all.contains("Apache") && all.contains("CentOS") -> "Linux (CentOS + Apache)"
            all.contains("Apache") || all.contains("Tomcat") -> "Linux (Apache)"
            all.contains("nginx") -> "Linux (nginx)"
            all.contains("IIS") || all.contains("Microsoft") -> "Windows (IIS)"
            all.contains("OpenSSH") && all.contains("Ubuntu") -> "Linux (Ubuntu)"
            all.contains("OpenSSH") && all.contains("Debian") -> "Linux (Debian)"
            all.contains("OpenSSH") -> "Linux (OpenSSH)"
            all.contains("SSH") && all.contains("2.") -> "Linux/Unix"
            all.contains("FTP") && all.contains("vsFTPd") -> "Linux (vsFTPd)"
            all.contains("SMB") || all.contains("445") -> "Windows/Linux SMB"
            all.contains("RDP") || all.contains("3389") -> "Windows (RDP)"
            all.contains("MySQL") && all.contains("3306") -> "Database server"
            all.contains("HTTP") && all.contains("401") -> "Router (Auth required)"
            else -> ""
        }
    }

    // ─── Update results ───
    private fun updateResults(results: ConcurrentHashMap<String, MutableList<String>>, os: ConcurrentHashMap<String, String>) {
        val sb = StringBuilder()
        val sorted = results.entries.sortedBy { it.key }
        var hostNum = 1
        for ((host, svcs) in sorted) {
            // Host header - make it a clickable link
            sb.appendLine("═ $hostNum. http://$host/ ${os[host]?.let { "[$it]" } ?: ""}")
            for (svc in svcs) {
                // Service may contain newlines (from path discovery) - indent each line
                val lines = svc.split("\n")
                for ((idx, line) in lines.withIndex()) {
                    if (idx == 0) {
                        sb.appendLine("   \u2514 $line")
                    } else {
                        sb.appendLine("      $line")
                    }
                }
            }
            sb.appendLine()
            hostNum++
        }
        tvResults.text = sb.toString().trimStart()
        tvResults.movementMethod = LinkMovementMethod.getInstance()
        
        // Summary with host count + open ports count
        val totalPorts = results.values.sumOf { it.size }
        tvSummary.text = "${results.size} host(s) \u00B7 $totalPorts open port(s)"
    }

    // ─── Ports ───
    private fun getAllPorts(): IntArray {
        val web = intArrayOf(80, 81, 82, 88, 443, 444, 3000, 4000, 5000, 5001, 7000, 7070, 7443, 7547, 8000, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8180, 8222, 8243, 8280, 8443, 8444, 8530, 8531, 8649, 8800, 8834, 8880, 8888, 8889, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9100, 9200, 9290, 9300, 9418, 9443, 9600, 9800, 9999, 10000, 10001, 10080, 12345, 13337, 16010, 16379, 17000, 17001, 20000, 22000, 25565, 27017, 31337, 32400, 32764, 49154, 49155, 49156, 50000, 50100, 50200, 61616, 64738, 65535)
        val other = intArrayOf(7, 9, 11, 13, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 49, 53, 67, 68, 69, 70, 79, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 194, 199, 201, 255, 259, 264, 280, 301, 306, 311, 340, 366, 389, 411, 412, 413, 427, 428, 434, 443, 445, 464, 465, 475, 497, 500, 502, 512, 513, 514, 515, 520, 521, 524, 540, 542, 543, 544, 546, 547, 548, 549, 550, 552, 553, 554, 556, 560, 561, 563, 564, 565, 566, 567, 585, 587, 601, 614, 623, 625, 626, 630, 631, 636, 639, 645, 646, 647, 648, 651, 653, 654, 655, 657, 660, 674, 688, 691, 694, 698, 700, 701, 702, 706, 707, 712, 713, 715, 720, 722, 726, 727, 729, 730, 731, 739, 740, 741, 742, 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761, 762, 763, 764, 765, 767, 768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 808, 843, 873, 886, 902, 903, 911, 912, 953, 981, 987, 990, 992, 993, 994, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1132, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1194, 1198, 1199, 1200, 1201, 1213, 1214, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1418, 1421, 1433, 1434, 1457, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1701, 1717, 1718, 1719, 1720, 1721, 1723, 1726, 1731, 1741, 1752, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1813, 1839, 1840, 1852, 1862, 1863, 1864, 1875, 1880, 1883, 1890, 1892, 1893, 1894, 1896, 1898, 1899, 1900, 1901, 1905, 1907, 1908, 1909, 1910, 1911, 1912, 1913, 1914, 1915, 1916, 1917, 1918, 1919, 1920, 1921, 1922, 1923, 1924, 1925, 1926, 1927, 1928, 1929, 1930, 1931, 1932, 1933, 1934, 1935, 1936, 1937, 1938, 1939, 1940, 1941, 1942, 1943, 1944, 1945, 1946, 1947, 1948, 1949, 1950, 1951, 1952, 1953, 1954, 1955, 1956, 1957, 1958, 1959, 1960, 1961, 1962, 1963, 1964, 1965, 1966, 1967, 1968, 1969, 1970, 1971, 1972, 1973, 1974, 1975, 1976, 1977, 1978, 1979, 1980, 1981, 1982, 1983, 1984, 1985, 1986, 1987, 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029, 2030, 2031, 2032, 2033, 2034, 2035, 2036, 2037, 2038, 2040, 2041, 2042, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2180, 2181, 2190, 2191, 2192, 2193, 2196, 2197, 2199, 2200, 2201, 2202, 2213, 2220, 2221, 2222, 2223, 2224, 2225, 2226, 2227, 2228, 2229, 2230, 2231, 2232, 2233, 2234, 2235, 2236, 2237, 2238, 2239, 2240, 2241, 2242, 2243, 2244, 2245, 2246, 2247, 2248, 2249, 2250, 2251, 2252, 2253, 2254, 2255, 2256, 2257, 2258, 2259, 2260, 2261, 2262, 2263, 2264, 2265, 2266, 2267, 2268, 2269, 2270, 2271, 2272, 2273, 2274, 2275, 2276, 2277, 2278, 2279, 2280, 2281, 2282, 2283, 2284, 2285, 2286, 2287, 2288, 2289, 2290, 2291, 2292, 2293, 2294, 2295, 2296, 2297, 2298, 2299, 2300, 2301, 2302, 2303, 2304, 2305, 2306, 2307, 2308, 2309, 2310, 2311, 2312, 2313, 2314, 2315, 2316, 2317, 2318, 2319, 2320, 2321, 2322, 2323, 2324, 2325, 2326, 2327, 2328, 2329, 2330, 2331, 2332, 2333, 2334, 2335, 2336, 2337, 2338, 2339, 2340, 2341, 2342, 2343, 2344, 2345, 2346, 2347, 2348, 2349, 2350, 2351, 2352, 2353, 2354, 2355, 2356, 2357, 2358, 2359, 2360, 2361, 2362, 2363, 2364, 2365, 2366, 2367, 2368, 2369, 2370, 2371, 2372, 2373, 2374, 2375, 2376, 2377, 2378, 2379, 2380, 2381, 2382, 2383, 2384, 2385, 2386, 2387, 2388, 2389, 2390, 2391, 2393, 2394, 2395, 2396, 2397, 2398, 2399, 2400, 2401, 2402, 2403, 2404, 2405, 2420, 2421, 2422, 2423, 2424, 2425, 2426, 2427, 2428, 2429, 2430, 2431, 2432, 2433, 2434, 2435, 2436, 2440, 2441, 2442, 2443, 2444, 2445, 2446, 2447, 2448, 2450, 2451, 2452, 2453, 2454, 2455, 2456, 2457, 2458, 2459, 2460, 2461, 2462, 2463, 2464, 2465, 2466, 2467, 2468, 2469, 2470, 2471, 2472, 2473, 2474, 2475, 2476, 2477, 2478, 2479, 2480, 2481, 2482, 2483, 2484, 2485, 2486, 2487, 2488, 2489, 2490, 2491, 2492, 2493, 2494, 2495, 2496, 2497, 2498, 2499, 2500, 2501, 2502, 2503, 2504, 2505, 2506, 2507, 2508, 2509, 2510, 2511, 2512, 2513, 2514, 2515, 2516, 2517, 2518, 2519, 2520, 2521, 2522, 2523, 2524, 2525, 2526, 2527, 2528, 2529, 2530, 2531, 2532, 2533, 2534, 2535, 2536, 2537, 2538, 2539, 2540, 2541, 2542, 2543, 2544, 2545, 2546, 2547, 2548, 2549, 2550, 2551, 2552, 2553, 2554, 2555, 2556, 2557, 2558, 2559, 2560, 2561, 2562, 2563, 2564, 2565, 2566, 2567, 2568, 2569, 2570, 2571, 2572, 2573, 2574, 2575, 2576, 2577, 2578, 2579, 2580, 2581, 2582, 2583, 2584, 2585, 2586, 2587, 2588, 2589, 2590, 2591, 2592, 2593, 2594, 2595, 2596, 2597, 2598, 2599, 2600, 2601, 2602, 2603, 2604, 2605, 2606, 2607, 2608, 2609, 2610, 2611, 2612, 2613, 2614, 2615, 2616, 2617, 2618, 2619, 2620, 2621, 2622, 2623, 2624, 2625, 2626, 2627, 2628, 2629, 2630, 2631, 2632, 2633, 2634, 2635, 2636, 2637, 2638, 2639, 2640, 2641, 2642, 2643, 2644, 2645, 2646, 2647, 2648, 2649, 2650, 2651, 2652, 2653, 2654, 2655, 2656, 2657, 2658, 2659, 2660, 2661, 2662, 2663, 2664, 2665, 2666, 2667, 2668, 2669, 2670, 2671, 2672, 2673, 2674, 2675, 2676, 2677, 2678, 2679, 2680, 2681, 2682, 2683, 2684, 2685, 2686, 2687, 2688, 2689, 2690, 2691, 2692, 2693, 2694, 2695, 2696, 2697, 2698, 2699, 2700, 2701, 2702, 2703, 2704, 2705, 2706, 2707, 2708, 2709, 2710, 2711, 2712, 2713, 2714, 2715, 2716, 2717, 2718, 2719, 2720, 2721, 2722, 2723, 2724, 2725, 2726, 2727, 2728, 2729, 2730, 2731, 2732, 2733, 2734, 2735, 2736, 2737, 2738, 2739, 2740, 2741, 2742, 2743, 2744, 2745, 2746, 2747, 2748, 2749, 2750, 2751, 2752, 2753, 2754, 2755, 2756, 2757, 2758, 2759, 2760, 2761, 2762, 2763, 2764, 2766, 2767, 2768, 2769, 2770, 2771, 2772, 2773, 2774, 2775, 2776, 2777, 2778, 2779, 2780, 2781, 2782, 2783, 2784, 2785, 2786, 2787, 2788, 2789, 2790, 2791, 2792, 2793, 2794, 2795, 2796, 2797, 2798, 2799, 2800, 2801, 2802, 2803, 2804, 2805, 2806, 2807, 2808, 2809, 2810, 2811, 2812, 2813, 2814, 2815, 2816, 2817, 2818, 2819, 2820, 2821, 2822, 2823, 2824, 2825, 2826, 2827, 2828, 2829, 2830, 2831, 2832, 2833, 2834, 2835, 2836, 2837, 2838, 2839, 2840, 2841, 2842, 2843, 2844, 2845, 2846, 2847, 2848, 2849, 2850, 2851, 2852, 2853, 2854, 2855, 2856, 2857, 2858, 2859, 2860, 2861, 2862, 2863, 2864, 2865, 2866, 2867, 2868, 2869, 2870, 2871, 2872, 2873, 2874, 2875, 2876, 2877, 2878, 2879, 2880, 2881, 2882, 2883, 2884, 2885, 2886, 2887, 2888, 2889, 2890, 2891, 2892, 2893, 2894, 2895, 2896, 2897, 2898, 2899, 2900, 2901, 2902, 2903, 2904, 2905, 2906, 2907, 2908, 2909, 2910, 2911, 2912, 2913, 2915, 2916, 2917, 2918, 2919, 2920, 2921, 2922, 2923, 2924, 2925, 2926, 2927, 2928, 2929, 2930, 2931, 2932, 2933, 2934, 2935, 2936, 2937, 2938, 2939, 2940, 2941, 2942, 2943, 2944, 2945, 2946, 2947, 2948, 2949, 2950, 2951, 2952, 2953, 2954, 2955, 2956, 2957, 2958, 2959, 2960, 2961, 2962, 2963, 2964, 2965, 2966, 2967, 2968, 2969, 2970, 2971, 2972, 2973, 2974, 2975, 2976, 2977, 2978, 2979, 2980, 2981, 2982, 2983, 2984, 2985, 2986, 2987, 2988, 2989, 2990, 2991, 2992, 2993, 2994, 2995, 2996, 2997, 2998, 2999, 3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010, 3011, 3012, 3013, 3014, 3015, 3016, 3017, 3018, 3019, 3020, 3021, 3022, 3023, 3024, 3025, 3026, 3027, 3028, 3029, 3030, 3031, 3032, 3033, 3034, 3035, 3036, 3037, 3038, 3039, 3040, 3041, 3042, 3043, 3044, 3045, 3046, 3047, 3048, 3049, 3050, 3051, 3052, 3053, 3054, 3055, 3056, 3057, 3058, 3059, 3060, 3061, 3062, 3063, 3064, 3065, 3066, 3067, 3068, 3069, 3070, 3071, 3072, 3073, 3074, 3075, 3076, 3077, 3078, 3079, 3080, 3081, 3082, 3083, 3084, 3085, 3086, 3087, 3088, 3089, 3090, 3091, 3092, 3093, 3094, 3095, 3096, 3097, 3098, 3099, 3100, 3101, 3102, 3103, 3104, 3105, 3106, 3107, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115, 3116, 3117, 3118, 3119, 3120, 3121, 3122, 3123, 3124, 3125, 3126, 3127, 3128, 3129, 3130, 3131, 3132, 3133, 3134, 3135, 3136, 3137, 3138, 3139, 3140, 3141, 3142, 3143, 3144, 3145, 3146, 3147, 3148, 3149, 3150, 3151, 3152, 3153, 3154, 3155, 3156, 3157, 3158, 3159, 3160, 3161, 3162, 3163, 3164, 3165, 3166, 3167, 3168, 3169, 3170, 3171, 3172, 3173, 3174, 3175, 3176, 3177, 3178, 3179, 3180, 3181, 3182, 3183, 3184, 3185, 3186, 3187, 3188, 3189, 3190, 3191, 3192, 3193, 3194, 3195, 3196, 3197, 3198, 3199, 3200, 3201, 3202, 3203, 3204, 3205, 3206, 3207, 3208, 3209, 3210, 3211, 3212, 3213, 3214, 3215, 3216, 3217, 3218, 3219, 3220, 3221, 3222, 3223, 3224, 3225, 3226, 3227, 3228, 3229, 3230, 3231, 3232, 3233, 3234, 3235, 3236, 3237, 3238, 3239, 3240, 3241, 3242, 3243, 3244, 3245, 3246, 3247, 3248, 3249, 3250, 3251, 3252, 3253, 3254, 3255, 3256, 3257, 3258, 3259, 3260, 3261, 3262, 3263, 3264, 3265, 3266, 3267, 3268, 3269, 3270, 3271, 3272, 3273, 3274, 3275, 3276, 3277, 3278, 3279, 3280, 3281, 3282, 3283, 3284, 3285, 3286, 3287, 3288, 3289, 3290, 3291, 3292, 3293, 3294, 3295, 3296, 3297, 3298, 3299, 3300, 3301, 3302, 3303, 3304, 3305, 3306, 3307, 3308, 3309, 3310, 3311, 3312, 3313, 3314, 3315, 3316, 3317, 3318, 3319, 3320, 3321, 3322, 3323, 3324, 3325, 3326, 3327, 3328, 3329, 3330, 3331, 3332, 3333, 3334, 3335, 3336, 3337, 3338, 3339, 3340, 3341, 3342, 3343, 3344, 3345, 3346, 3347, 3348, 3349, 3350, 3351, 3352, 3353, 3354, 3355, 3356, 3357, 3358, 3359, 3360, 3361, 3362, 3363, 3364, 3365, 3366, 3367, 3368, 3369, 3370, 3371, 3372, 3373, 3374, 3375, 3376, 3377, 3378, 3379, 3380, 3381, 3382, 3383, 3384, 3385, 3386, 3387, 3388, 3389, 3390, 3391, 3392, 3393, 3394, 3395, 3396, 3397, 3398, 3399, 3400, 3401, 3402, 3403, 3404, 3405, 3406, 3407, 3408, 3409, 3410, 3411, 3412, 3413, 3414, 3415, 3416, 3417, 3418, 3419, 3420, 3421, 3422, 3423, 3424, 3425, 3426, 3427, 3428, 3429, 3430, 3431, 3432, 3433, 3434, 3435, 3436, 3437, 3438, 3439, 3440, 3441, 3442, 3443, 3444, 3445, 3446, 3447, 3448, 3449, 3450, 3451, 3452, 3453, 3454, 3455, 3456, 3457, 3458, 3459, 3460, 3461, 3462, 3463, 3464, 3465, 3466, 3467, 3468, 3469, 3470, 3471, 3472, 3473, 3474, 3475, 3476, 3477, 3478, 3479, 3480, 3481, 3482, 3483, 3484, 3485, 3486, 3487, 3488, 3489, 3490, 3491, 3492, 3493, 3494, 3495, 3496, 3497, 3498, 3499, 3500, 3501, 3502, 3503, 3504, 3505, 3506, 3507, 3508, 3509, 3510, 3511, 3512, 3513, 3514, 3515, 3516, 3517, 3518, 3519, 3520, 3521, 3522, 3523, 3524, 3525, 3526, 3527, 3528, 3529, 3530, 3531, 3532, 3533, 3534, 3535, 3536, 3537, 3538, 3539, 3540, 3541, 3542, 3543, 3544, 3545, 3546, 3547, 3548, 3549, 3550, 3551, 3552, 3553, 3554, 3555, 3556, 3557, 3558, 3559, 3560, 3561, 3562, 3563, 3564, 3565, 3566, 3567, 3568, 3569, 3570, 3571, 3572, 3573, 3574, 3575, 3576, 3577, 3578, 3579, 3580, 3581, 3582, 3583, 3584, 3585, 3586, 3587, 3588, 3589, 3590, 3591, 3592, 3593, 3594, 3595, 3596, 3597, 3598, 3599, 3600, 3601, 3602, 3603, 3604, 3605, 3606, 3607, 3608, 3609, 3610, 3611, 3612, 3613, 3614, 3615, 3616, 3617, 3618, 3619, 3620, 3621, 3622, 3623, 3624, 3625, 3626, 3627, 3628, 3629, 3630, 3631, 3632, 3633, 3634, 3635, 3636, 3637, 3638, 3639, 3640, 3641, 3642, 3643, 3644, 3645, 3646, 3647, 3648, 3649, 3650, 3651, 3652, 3653, 3654, 3655, 3656, 3657, 3658, 3659, 3660, 3661, 3662, 3663, 3664, 3665, 3666, 3667, 3668, 3669, 3670, 3671, 3672, 3673, 3674, 3675, 3676, 3677, 3678, 3679, 3680, 3681, 3682, 3683, 3684, 3685, 3686, 3687, 3688, 3689, 3690, 3691, 3692, 3693, 3694, 3695, 3696, 3697, 3698, 3699, 3700, 3701, 3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710, 3711, 3712, 3713, 3714, 3715, 3716, 3717, 3718, 3719, 3720, 3721, 3722, 3723, 3724, 3725, 3726, 3727, 3728, 3729, 3730, 3731, 3732, 3733, 3734, 3735, 3736, 3737, 3738, 3739, 3740, 3741, 3742, 3743, 3744, 3745, 3746, 3747, 3748, 3749, 3750, 3751, 3752, 3753, 3754, 3755, 3756, 3757, 3758, 3759, 3760, 3761, 3762, 3763, 3764, 3765, 3766, 3767, 3768, 3769, 3770, 3771, 3772, 3773, 3774, 3775, 3776, 3777, 3778, 3779, 3780, 3781, 3782, 3783, 3784, 3785)
        return web + other
    }

    private fun guessService(port: Int): String = when (port) {
        21 -> "FTP"; 22 -> "SSH"; 23 -> "Telnet"; 25 -> "SMTP"; 53 -> "DNS"
        69 -> "TFTP"; 79 -> "Finger"; 80, 81, 82, 88 -> "HTTP"; 110 -> "POP3"
        111 -> "RPC"; 113 -> "Ident"; 119 -> "NNTP"; 123 -> "NTP"
        135 -> "MSRPC"; 137, 138, 139 -> "NetBIOS"; 143 -> "IMAP"
        161, 162 -> "SNMP"; 179 -> "BGP"; 194 -> "IRC"
        389 -> "LDAP"; 443, 444 -> "HTTPS"; 445 -> "SMB"
        465 -> "SMTPS"; 500 -> "IKE"; 502 -> "Modbus"
        512 -> "rexec"; 513 -> "rlogin"; 514 -> "Syslog"
        520 -> "RIP"; 521 -> "RIPng"; 540 -> "UUCp"
        546, 547 -> "DHCPv6"; 554 -> "RTSP"; 563 -> "NNTPs"
        585 -> "IMAP4+SSL"; 587 -> "SMTP-Sub"; 623 -> "IPMI"
        631 -> "IPP"; 636 -> "LDAPS"; 646 -> "LDP"
        990 -> "FTPS"; 992 -> "TelnetS"; 993 -> "IMAPS"
        995 -> "POP3S"; 1080 -> "SOCKS"; 1194 -> "OpenVPN"
        1433, 1434 -> "MSSQL"; 1494 -> "Citrix"; 1521 -> "Oracle"
        1524 -> "Ingres"; 1701 -> "L2TP"; 1720 -> "H.323"
        1723 -> "PPTP"; 1741 -> "Lotus"; 1755 -> "WMS"
        1812, 1813 -> "RADIUS"; 1883 -> "MQTT"; 1900 -> "UPnP"
        1993 -> "SNMP-Trap"; 2000 -> "BW-Test"; 2001 -> "DC"
        2049 -> "NFS"; 2082, 2083 -> "cPanel"; 2086, 2087 -> "WHM"
        2095, 2096 -> "WebMail"; 2100 -> "OracleXDB"
        2181 -> "ZooKeeper"; 2222 -> "SSH-Alt"; 2375, 2376 -> "Docker"
        3128 -> "Squid"; 3260 -> "iSCSI"; 3299 -> "Dev-Web"
        3306 -> "MySQL"; 3389, 3390 -> "RDP"; 4000 -> "Web-Alt"
        4222 -> "Web-Alt2"; 4343, 4443 -> "HTTPS-Alt"
        4848 -> "GlassFish"; 4899 -> "RAdmin"
        5000, 5001 -> "Web-Alt3"; 5432 -> "PostgreSQL"
        5555 -> "ADB"; 5631, 5632 -> "VNC"
        5666 -> "Nagios"; 5800 -> "VNC-HTTP"
        5900, 5901 -> "VNC"; 5984 -> "CouchDB"
        6000, 6001 -> "X11"; 6379 -> "Redis"
        6646 -> "Web-Alt4"; 6666 -> "Web-Alt5"
        6667 -> "IRC"; 7000, 7001 -> "Web-Alt6"
        7070, 7077 -> "Web-Alt7"; 7443 -> "HTTPS-Alt2"
        7547 -> "CWMP"; 7675 -> "Web-Alt8"; 7777 -> "Web-Alt9"
        8000 -> "HTTP-Alt"; 8008 -> "HTTP-Alt2"
        8080 -> "HTTP-Proxy"; 8081, 8082 -> "HTTP-Alt3"
        8118 -> "Privoxy"; 8180 -> "HTTP-Alt4"
        8222 -> "HTTP-Alt5"; 8243 -> "HTTPS-Alt3"
        8280 -> "HTTP-Alt6"; 8291 -> "Winbox"
        8443 -> "HTTPS-Alt4"; 8530, 8531 -> "HTTP-Alt7"
        8649 -> "Ganglia"; 8800 -> "Web-Alt10"
        8834 -> "Nessus"; 8880 -> "HTTP-Alt8"
        8888 -> "Web-Alt11"; 8889 -> "Web-Alt12"
        8983 -> "Solr"; 9000 -> "Web-Alt13"
        9001 -> "Tor"; 9043 -> "WebSphere"
        9060 -> "Web-Alt14"; 9080 -> "HTTP-Alt9"
        9090 -> "Web-Alt15"; 9091 -> "Web-Alt16"
        9100 -> "Printer"; 9200 -> "Elasticsearch"
        9290, 9300 -> "Elastic"; 9418 -> "Git"
        9443 -> "HTTPS-Alt5"; 9600 -> "Web-Alt17"
        9800 -> "Web-Alt18"; 9999 -> "Web-Alt19"
        10000 -> "Web-Alt20"; 10001 -> "Web-Alt21"
        10080 -> "HTTP-Alt10"; 11211 -> "Memcached"
        12345 -> "Web-Alt22"; 13337 -> "Web-Alt23"
        16010, 16379 -> "Web-Alt24"; 17000, 17001 -> "Web-Alt25"
        20000, 22000 -> "Web-Alt26"; 25565 -> "Minecraft"
        27017 -> "MongoDB"; 31337 -> "BackOrifice"
        32400 -> "Plex"; 32764 -> "Router-Exploit"
        49152, 49153, 49154, 49155, 49156, 49157 -> "WinRPC"
        50000 -> "Web-Alt27"; 50100 -> "Web-Alt28"
        50200 -> "Web-Alt29"; 61616 -> "Web-Alt30"
        64738 -> "Mumble"; 65535 -> "Web-Alt31"
        else -> "?"
    }


    // ─── Hidden Camera Scanner ───
    private fun cameraScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        AlertDialog.Builder(this)
            .setTitle("Camera Scanner")
            .setMessage("Scanning for hidden IP cameras on $target\n\nChecks common camera ports:\n554 (RTSP), 8899 (ONVIF), 34567 (Hikvision),\n37777 (Dahua), 80/443/8080/8443 (Web)\n\nAlso probes for camera-specific HTTP responses.")
            .setPositiveButton("Scan") { _, _ -> runCameraScan(target) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private val cameraPorts = intArrayOf(
        80, 443, 554, 8080, 8443, 8899, 34567, 37777,
        5000, 7000, 8000, 8554, 9000, 10000, 37215, 49152
    )

    private data class CameraInfo(
        val ip: String,
        val port: Int,
        val manufacturer: String,
        val model: String,
        val type: String
    )

    private fun runCameraScan(target: String) {
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Scanning for hidden cameras...\n"
        tvSummary.text = ""
        status("Camera scan...", "#6A1B9A", true)
        showProgress()

        Thread {
            val cameras = ConcurrentHashMap<String, MutableList<String>>()
            val startTime = System.currentTimeMillis()

            try {
                val targets = autoExpandTarget(target)
                if (targets.isEmpty()) {
                    uiPost("Invalid target", "#C62828", false)
                    isScanning = false
                    return@Thread
                }
                uiPost("Checking ${targets.size} host(s) for cameras...", "#6A1B9A", true)

                val latch = CountDownLatch(targets.size)
                val pool = Executors.newFixedThreadPool(30)
                val progCount = AtomicInteger(0)

                for (ip in targets) {
                    if (!isScanning) { latch.countDown(); continue }
                    pool.execute {
                        try {
                            val foundCameras = mutableListOf<String>()

                            for (port in cameraPorts) {
                                if (!isScanning) break
                                val cam = probeCamera(ip, port)
                                if (cam != null) {
                                    synchronized(foundCameras) {
                                        foundCameras.add("$cam")
                                    }
                                }
                            }

                            if (foundCameras.isNotEmpty()) {
                                synchronized(cameras) {
                                    cameras[ip] = foundCameras
                                }
                                ui.post { updateCameraResults(cameras) }
                            }
                        } finally {
                                latch.countDown()
                                val done = progCount.incrementAndGet()
                                ui.post { updateProgress(done, targets.size) }
                            }
                    }
                }

                pool.shutdown()
                latch.await()
                ui.post { updateCameraResults(cameras) }

            } catch (e: Exception) {
                uiPost("Error: ${e.message}", "#C62828", false)
            }

            val elapsed = System.currentTimeMillis() - startTime
            val summary = "\n── Done in ${elapsed / 1000}s ──  ${cameras.size} camera(s) found"
            ui.post {
                tvSummary.text = "$summary\n\u26A0\uFE0F Review privacy settings if unexpected cameras found"
                status("${cameras.size} camera(s) in ${elapsed / 1000}s", "#6A1B9A", true)
                toast("${cameras.size} camera(s) found")
            }
            hideProgress()
            isScanning = false
        }.start()
    }

    private fun probeCamera(ip: String, port: Int): String? {
        return try {
            val s = Socket()
            s.connect(InetSocketAddress(ip, port), getTimeout().coerceAtMost(1000))
            if (!s.isConnected) { s.close(); return null }

            var result: String? = null
            val isHttpPort = port in intArrayOf(80, 443, 8080, 8443, 8000, 9000, 10000, 5000, 7000)

            if (isHttpPort) {
                try {
                    val protocol = if (port == 443 || port == 8443) "https" else "http"
                    val conn = URL("$protocol://$ip:$port/").openConnection() as HttpURLConnection
                    conn.connectTimeout = 800
                    conn.readTimeout = 800
                    conn.setRequestProperty("User-Agent", "Mozilla/5.0 NetScan/1.1")
                    val code = try { conn.responseCode } catch (_: Exception) { 0 }
                    val server = conn.getHeaderField("Server") ?: ""
                    val www = conn.getHeaderField("WWW-Authenticate") ?: ""
                    val ct = conn.getHeaderField("Content-Type") ?: ""

                    // Camera signatures
                    var title = ""
                    try {
                        val reader = BufferedReader(InputStreamReader(
                            if (code in 200..399) conn.inputStream else conn.errorStream, "UTF-8"), 512)
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            val m = Regex("<title[^>]*>(.*?)</title>", RegexOption.IGNORE_CASE).find(line ?: "")
                            if (m != null) { title = m.groupValues[1].take(60).trim(); break }
                            // Check for camera-specific keywords in body
                            val lower = (line ?: "").lowercase()
                            if (lower.contains("hikvision") || lower.contains("dahua") ||
                                lower.contains("onvif") || lower.contains("rtsp") ||
                                lower.contains("ip camera") || lower.contains("webcam") ||
                                lower.contains("network camera")) {
                                if (title.isEmpty()) title = "Camera detected"
                            }
                        }
                        reader.close()
                    } catch (_: Exception) { }
                    conn.disconnect()

                    // Check camera indicators
                    val isCamera = title.lowercase().contains("camera") ||
                        title.lowercase().contains("hikvision") ||
                        title.lowercase().contains("dahua") ||
                        title.lowercase().contains("webcam") ||
                        title.lowercase().contains("onvif") ||
                        title.lowercase().contains("surveillance") ||
                        title.lowercase().contains("nvr") ||
                        title.lowercase().contains("dvr") ||
                        server.contains("Hikvision") ||
                        server.contains("Dahua") ||
                        server.contains("IP Camera") ||
                        server.contains("Network Camera") ||
                        www.lowercase().contains("camera") ||
                        www.lowercase().contains("digest") ||
                        ct.contains("video")

                    if (isCamera || title.isNotEmpty() && title.lowercase().contains("camera")) {
                        var mfg = guessCameraMfg(title, server, www)
                        if (mfg.isEmpty()) mfg = guessCameraMfgFromPort(port)
                        result = "\uD83D\uDCF7 Port $port - ${mfg.ifEmpty { "Unknown" }}"
                        if (title.isNotEmpty() && !title.lowercase().contains("camera") &&
                            !title.lowercase().contains("hikvision") && !title.lowercase().contains("dahua")) {
                            result += " \"$title\""
                        }
                        if (www.isNotEmpty()) result += " [Auth]"
                    }
                } catch (_: Exception) { }
            } else {
                // Non-HTTP ports: RTSP, ONVIF, etc.
                try {
                    // RTSP probe
                    if (port == 554 || port == 8554) {
                        s.getOutputStream().write(("OPTIONS rtsp://$ip:$port RTSP/1.0\r\n" +
                                "CSeq: 1\r\n\r\n").toByteArray())
                        val resp = BufferedReader(InputStreamReader(s.getInputStream(), "ISO-8859-1"))
                        val response = resp.readLine() ?: ""
                        if (response.contains("RTSP")) {
                            result = "\uD83D\uDCF7 Port $port (RTSP) - Camera stream"
                        }
                    }
                    // ONVIF
                    if (port == 8899 || port == 5000) {
                        val onvifReq = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                            "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
                            "<s:Body>" +
                            "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>" +
                            "</s:Body></s:Envelope>"
                        s.getOutputStream().write(onvifReq.toByteArray())
                        val resp = BufferedReader(InputStreamReader(s.getInputStream(), "ISO-8859-1"))
                        val onvifResp = StringBuilder()
                        var line: String?
                        while (resp.readLine().also { line = it } != null) {
                            onvifResp.append(line)
                        }
                        if (onvifResp.toString().contains("ONVIF") ||
                            onvifResp.toString().contains("Capabilities")) {
                            result = "\uD83D\uDCF7 Port $port (ONVIF) - Network camera"
                        }
                    }
                    // Hikvision port
                    if (port == 34567) {
                        result = "\uD83D\uDCF7 Port $port (Hikvision SDK)"
                    }
                    // Dahua port
                    if (port == 37777) {
                        result = "\uD83D\uDCF7 Port $port (Dahua SDK)"
                    }
                    if (port == 37215) {
                        result = "\uD83D\uDCF7 Port $port (Hikvision backdoor)"
                    }
                } catch (_: Exception) { }
            }

            s.close()
            result
        } catch (_: Exception) { null }
    }

    private fun guessCameraMfg(title: String, server: String, www: String): String {
        val all = "$title $server $www".lowercase()
        return when {
            all.contains("hikvision") -> "Hikvision"
            all.contains("dahua") -> "Dahua"
            all.contains("tp-link") || all.contains("tp link") -> "TP-Link"
            all.contains("reolink") -> "Reolink"
            all.contains("amcrest") -> "Amcrest"
            all.contains("foscam") -> "Foscam"
            all.contains("axis") -> "Axis"
            all.contains("bosch") -> "Bosch"
            all.contains("panasonic") -> "Panasonic"
            all.contains("sony") -> "Sony"
            all.contains("vivotek") -> "Vivotek"
            all.contains("ubiquiti") || all.contains("unifi") -> "Ubiquiti"
            all.contains("dlink") || all.contains("d-link") -> "D-Link"
            all.contains("huawei") -> "Huawei"
            all.contains("xiaomi") || all.contains("mi camera") -> "Xiaomi"
            all.contains("ezviz") -> "Ezviz"
            all.contains("imou") -> "Imou"
            all.contains("tenda") -> "Tenda"
            all.contains("netvue") -> "Netvue"
            else -> ""
        }
    }

    private fun guessCameraMfgFromPort(port: Int): String = when (port) {
        34567 -> "Hikvision"
        37777 -> "Dahua"
        37215 -> "Hikvision"
        8899 -> "ONVIF"
        554, 8554 -> "RTSP"
        else -> ""
    }

    private fun updateCameraResults(cameras: ConcurrentHashMap<String, MutableList<String>>) {
        val sb = StringBuilder()
        var num = 1
        for ((ip, cams) in cameras) {
            sb.appendLine("\uD83D\uDCF7 $num. http://$ip/")
            for (cam in cams) {
                sb.appendLine("   \u2514 $cam")
            }
            sb.appendLine()
            num++
        }
        tvResults.text = sb.toString().trimStart()
        tvResults.movementMethod = LinkMovementMethod.getInstance()
        tvSummary.text = "${cameras.size} camera(s) found"
    }


    // ─── Router Scanner ───
    private fun routerScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        AlertDialog.Builder(this)
            .setTitle("Router Scanner")
            .setMessage("Scanning ALL devices for routers\nTarget: $target\n\nAuto-expanded to /24 subnet\nChecking common admin ports & paths and paths\nto identify router model & brand.\n\nScans for: MikroTik, TP-Link, Tenda,\nD-Link, ASUS, Netgear, Linksys,\nOpenWrt, DD-WRT, and more.")
            .setPositiveButton("Scan") { _, _ -> runRouterScan(target) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private val routerPorts = intArrayOf(
        80, 443, 8080, 8443, 8291, 7547, 5000, 7000,
        8081, 8082, 8888, 9000, 10000, 2000, 444, 81, 82, 88
    )

    private val routerPaths = arrayOf(
        "/", "/admin", "/admin/", "/login", "/login/",
        "/setup", "/setup/", "/config", "/config/",
        "/management", "/management/", "/status", "/status/",
        "/system", "/system/", "/router", "/router/",
        "/cgi-bin/", "/cgi-bin/login", "/cgi-bin/status",
        "/main", "/main/", "/home", "/home/",
        "/index.htm", "/index.html", "/login.htm", "/login.html"
    )

    private data class RouterInfo(
        val ip: String,
        val port: Int,
        val brand: String,
        val model: String,
        val firmware: String,
        val authType: String,
        val path: String
    )

    private fun runRouterScan(target: String) {
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Scanning for routers...\n"
        tvSummary.text = ""
        status("Router scan...", "#E65100", true)
        showProgress()

        Thread {
            val routers = ConcurrentHashMap<String, MutableList<String>>()
            val startTime = System.currentTimeMillis()

            try {
                val targets = autoExpandTarget(target)
                if (targets.isEmpty()) {
                    uiPost("Invalid target", "#C62828", false)
                    isScanning = false
                    return@Thread
                }
                uiPost("Checking ${targets.size} host(s) for routers...", "#E65100", true)

                val latch = CountDownLatch(targets.size)
                val pool = Executors.newFixedThreadPool(30)
                val progCount = AtomicInteger(0)

                for (ip in targets) {
                    if (!isScanning) { latch.countDown(); continue }
                    pool.execute {
                        try {
                            val foundRouters = mutableListOf<String>()

                            for (port in routerPorts) {
                                if (!isScanning) break
                                val info = probeRouter(ip, port)
                                if (info != null) {
                                    synchronized(foundRouters) {
                                        foundRouters.add(info)
                                    }
                                }
                            }

                            if (foundRouters.isNotEmpty()) {
                                synchronized(routers) {
                                    routers[ip] = foundRouters
                                }
                                ui.post { updateRouterResults(routers) }
                            }
                        } finally {
                                latch.countDown()
                                val done = progCount.incrementAndGet()
                                ui.post { updateProgress(done, targets.size) }
                            }
                    }
                }

                pool.shutdown()
                latch.await()
                ui.post { updateRouterResults(routers) }

            } catch (e: Exception) {
                uiPost("Error: ${e.message}", "#C62828", false)
            }

            val elapsed = System.currentTimeMillis() - startTime
            ui.post {
                tvSummary.text = "${routers.size} router(s) found in ${elapsed / 1000}s"
                status("${routers.size} router(s) in ${elapsed / 1000}s", "#E65100", true)
                toast("${routers.size} router(s) found")
            }
            hideProgress()
            isScanning = false
        }.start()
    }

    private fun probeRouter(ip: String, port: Int): String? {
        return try {
            val s = Socket()
            s.connect(InetSocketAddress(ip, port), getTimeout().coerceAtMost(1000))
            if (!s.isConnected) { s.close(); return null }

            var result: String? = null

            // Check if Winbox port (MikroTik)
            if (port == 8291) {
                s.close()
                return "\uD83C\uDF10 Port $port (Winbox) - MikroTik RouterOS"
            }

            // Check if CWMP/TR-069 port
            if (port == 7547) {
                // Try to get response
                try {
                    s.getOutputStream().write(("GET / HTTP/1.0\r\nHost: $ip\r\n\r\n").toByteArray())
                    val reader = BufferedReader(InputStreamReader(s.getInputStream(), "ISO-8859-1"))
                    val resp = reader.readLine() ?: ""
                    reader.close()
                    if (resp.contains("200")) {
                        s.close()
                        return "\uD83C\uDF10 Port $port (CWMP/TR-069) - Router management"
                    }
                } catch (_: Exception) { }
                s.close()
                return "\uD83C\uDF10 Port $port (CWMP) - Router"
            }

            // HTTP probe - check multiple paths
            val protocol = if (port in intArrayOf(443, 8443, 444)) "https" else "http"
            val base = "$protocol://$ip:$port"

            var bestInfo: RouterInfo? = null
            for (path in routerPaths) {
                try {
                    val conn = URL("$base$path").openConnection() as HttpURLConnection
                    conn.connectTimeout = 500
                    conn.readTimeout = 500
                    conn.instanceFollowRedirects = false
                    conn.setRequestProperty("User-Agent", "Mozilla/5.0 NetScan/1.1")

                    val code = try { conn.responseCode } catch (_: Exception) { 0 }
                    if (code == 0 || code == 404 || code == 410) { conn.disconnect(); continue }

                    val server = conn.getHeaderField("Server") ?: ""
                    val www = conn.getHeaderField("WWW-Authenticate") ?: ""
                    val ct = conn.getHeaderField("Content-Type") ?: ""

                    var title = ""
                    try {
                        val stream = if (code in 200..399) conn.inputStream else conn.errorStream
                        val reader = BufferedReader(InputStreamReader(stream, "UTF-8"), 512)
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            val m = Regex("<title[^>]*>(.*?)</title>", RegexOption.IGNORE_CASE).find(line ?: "")
                            if (m != null) { title = m.groupValues[1].take(80).trim(); break }
                        }
                        reader.close()
                    } catch (_: Exception) { }
                    conn.disconnect()

                    val brand = identifyRouterBrand(server, title, www)

                    if (brand.isNotEmpty() || code in 200..302) {
                        val model = identifyRouterModel(brand, title)
                        val firmware = extractFirmware(title)
                        val authType = if (www.isNotEmpty()) {
                            if (www.contains("Basic", ignoreCase = true)) "Basic Auth"
                            else if (www.contains("Digest", ignoreCase = true)) "Digest Auth"
                            else "Auth Required"
                        } else ""

                        val info = RouterInfo(ip, port, brand, model, firmware, authType, path)

                        // Prefer results with a known brand or login page
                        if (bestInfo == null || (brand.isNotEmpty() && bestInfo!!.brand.isEmpty())) {
                            bestInfo = info
                        }
                    }
                } catch (_: Exception) { }
            }

            s.close()

            if (bestInfo != null) {
                val info = bestInfo
                val parts = mutableListOf<String>()
                parts.add("\uD83C\uDF10 Port ${info.port}")
                if (info.brand.isNotEmpty()) parts.add(info.brand)
                if (info.model.isNotEmpty()) parts.add("\"${info.model}\"")
                if (info.firmware.isNotEmpty()) parts.add("[${info.firmware}]")
                if (info.authType.isNotEmpty()) parts.add("\uD83D\uDD12 ${info.authType}")
                if (info.path != "/") parts.add("@ ${info.path}")
                return parts.joinToString(" ")
            }

            null
        } catch (_: Exception) { null }
    }

    private fun identifyRouterBrand(server: String, title: String, www: String): String {
        val all = "$server $title $www".lowercase()
        return when {
            all.contains("mikrotik") || all.contains("routeros") -> "MikroTik"
            all.contains("routeros") -> "MikroTik"
            all.contains("tp-link") || all.contains("tp link") -> "TP-Link"
            all.contains("tenda") -> "Tenda"
            all.contains("d-link") || all.contains("dlink") -> "D-Link"
            all.contains("asus") -> "ASUS"
            all.contains("netgear") -> "Netgear"
            all.contains("linksys") || all.contains("cisco") -> "Cisco/Linksys"
            all.contains("huawei") -> "Huawei"
            all.contains("zte") -> "ZTE"
            all.contains("openwrt") -> "OpenWrt"
            all.contains("dd-wrt") || all.contains("ddwrt") -> "DD-WRT"
            all.contains("tomato") -> "Tomato"
            all.contains("ubiquiti") || all.contains("unifi") -> "Ubiquiti"
            all.contains("meraki") -> "Meraki"
            all.contains("arris") -> "Arris"
            all.contains("motorola") -> "Motorola"
            all.contains("sagemcom") -> "Sagemcom"
            all.contains("technicolor") -> "Technicolor"
            all.contains("fritz") || all.contains("avm") -> "AVM FRITZ!"
            all.contains("zyxel") -> "Zyxel"
            all.contains("totolink") -> "TOTOLINK"
            all.contains("mercusys") -> "Mercusys"
            all.contains("goahead") || all.contains("go ahead") -> "Router (GoAhead)"
            all.contains("mini_httpd") -> "Router (mini_httpd)"
            all.contains("httpd") && all.contains("router") -> "Generic Router"
            all.contains("boa") && !all.contains("python") -> "Router (Boa)"
            all.contains("thttpd") -> "Router (thttpd)"
            all.contains("lighttpd") -> "Linux (lighttpd)"
            all.contains("apache") && all.contains("ubuntu") -> "Linux (Ubuntu)"
            all.contains("apache") && all.contains("debian") -> "Linux (Debian)"
            all.contains("apache") -> "Linux (Apache)"
            all.contains("nginx") -> "Linux (nginx)"
            all.contains("iis") -> "Windows (IIS)"
            title.contains("router", ignoreCase = true) ||
            title.contains("login", ignoreCase = true) ||
            title.contains("admin", ignoreCase = true) ||
            title.contains("setup", ignoreCase = true) -> "Unknown Router"
            else -> ""
        }
    }

    private fun identifyRouterModel(brand: String, title: String): String {
        if (title.isEmpty()) return ""
        val t = title.trim()
        // Try to extract model number from title: "TL-WR841N", "AC1200", etc.
        val model = Regex("""[A-Z0-9]+[-][A-Z0-9]+""").find(t)
        if (model != null) return model.value
        val model2 = Regex("""((TL|DIR|RT|WR|WRT|WAN|LAN|AC|AX)[-]?[A-Z0-9]+)""", RegexOption.IGNORE_CASE).find(t)
        if (model2 != null) return model2.value.uppercase()
        // Return title if it looks like a model
        if (t.length < 40 && !t.lowercase().contains("login") && !t.lowercase().contains("admin")) {
            return t.take(30)
        }
        return ""
    }

    private fun extractFirmware(title: String): String {
        // Look for version numbers like "v1.0", "2.5.1", "2024"
        val ver = Regex("""v?\d+[.]\d+[.]?\d*""").find(title)
        if (ver != null) return ver.value
        val ver2 = Regex("""\d{4}""").find(title)
        if (ver2 != null) return ver2.value
        return ""
    }

    private fun updateRouterResults(routers: ConcurrentHashMap<String, MutableList<String>>) {
        val sb = StringBuilder()
        val sorted = routers.entries.sortedBy { it.key }
        var num = 1
        for ((ip, routerInfo) in sorted) {
            sb.appendLine("\uD83C\uDF10 $num. http://$ip/")
            for (info in routerInfo) {
                sb.appendLine("   \u2514 $info")
            }
            sb.appendLine()
            num++
        }
        tvResults.text = sb.toString().trimStart()
        tvResults.movementMethod = LinkMovementMethod.getInstance()
        tvSummary.text = "${routers.size} router(s) found"
    }


    // ─── Network Shares Scanner ───
    private fun sharesScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        AlertDialog.Builder(this)
            .setTitle("Shares Scanner")
            .setMessage("Scanning ALL devices for shares\nTarget: $target\n\nAuto-expanded to /24 subnet\nChecks for:\n• HTTP directory listings\n• FTP servers (anonymous)\n• SMB/CIFS shares\n• NFS exports\n• WebDAV\n\nScans common share ports.")
            .setPositiveButton("Scan") { _, _ -> runSharesScan(target) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private val sharePorts = intArrayOf(80, 8080, 21, 445, 139, 2049, 111, 135, 443, 8443, 8081, 5000, 7000, 8888, 9090, 9000)

    private fun runSharesScan(target: String) {
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Scanning for shares...\n"
        tvSummary.text = ""
        status("Shares scan...", "#33691E", true)
        showProgress()

        Thread {
            val shares = ConcurrentHashMap<String, MutableList<String>>()
            val startTime = System.currentTimeMillis()

            try {
                val targets = autoExpandTarget(target)
                if (targets.isEmpty()) {
                    uiPost("Invalid target", "#C62828", false)
                    isScanning = false
                    return@Thread
                }
                uiPost("Checking ${targets.size} host(s) for shares...", "#33691E", true)

                val latch = CountDownLatch(targets.size)
                val pool = Executors.newFixedThreadPool(30)
                val progCount = AtomicInteger(0)

                for (ip in targets) {
                    if (!isScanning) { latch.countDown(); continue }
                    pool.execute {
                        try {
                            val foundShares = mutableListOf<String>()

                            for (port in sharePorts) {
                                if (!isScanning) break
                                val share = probeShare(ip, port)
                                if (share != null) {
                                    synchronized(foundShares) { foundShares.add(share) }
                                }
                            }

                            if (foundShares.isNotEmpty()) {
                                synchronized(shares) { shares[ip] = foundShares }
                                ui.post { updateSharesResults(shares) }
                            }
                        } finally {
                                latch.countDown()
                                val done = progCount.incrementAndGet()
                                ui.post { updateProgress(done, targets.size) }
                            }
                    }
                }

                pool.shutdown()
                latch.await()
                ui.post { updateSharesResults(shares) }

            } catch (e: Exception) {
                uiPost("Error: ${e.message}", "#C62828", false)
            }

            val elapsed = System.currentTimeMillis() - startTime
            ui.post {
                tvSummary.text = "${shares.size} host(s) with shares in ${elapsed / 1000}s"
                status("${shares.size} host(s) with shares", "#33691E", true)
                toast("${shares.size} host(s) with shares")
            }
            hideProgress()
            isScanning = false
        }.start()
    }

    private fun probeShare(ip: String, port: Int): String? {
        return try {
            val s = Socket()
            s.connect(InetSocketAddress(ip, port), getTimeout().coerceAtMost(1000))
            if (!s.isConnected) { s.close(); return null }

            var result: String? = null

            when (port) {
                21 -> {
                    // FTP - check for anonymous access
                    try {
                        val reader = BufferedReader(InputStreamReader(s.getInputStream(), "ISO-8859-1"))
                        val banner = reader.readLine() ?: ""
                        if (banner.contains("FTP") || banner.contains("220")) {
                            s.close()
                            // Quick anonymous probe
                            val s2 = Socket()
                            s2.connect(InetSocketAddress(ip, port), 1000)
                            s2.getOutputStream().write("USER anonymous\r\n".toByteArray())
                            val r1 = BufferedReader(InputStreamReader(s2.getInputStream(), "ISO-8859-1"))
                            val resp1 = r1.readLine() ?: ""
                            s2.getOutputStream().write("PASS guest@\r\n".toByteArray())
                            val resp2 = r1.readLine() ?: ""
                            s2.close()
                            val isAnonymous = resp2.contains("230") || resp1.contains("331")
                            val ftpInfo = "Port 21 (FTP)${if (isAnonymous) " [ANONYMOUS]" else " [auth required]"}"
                            if (isAnonymous) result = "\uD83D\uDCC1 $ftpInfo - ${banner.take(60)}"
                            else result = "\uD83D\uDCC1 $ftpInfo"
                        }
                        reader.close()
                    } catch (_: Exception) { }
                }
                445 -> {
                    // SMB
                    s.close()
                    result = "\uD83D\uDCC1 Port 445 (SMB) - Windows file sharing"
                }
                139 -> {
                    // NetBIOS
                    s.close()
                    result = "\uD83D\uDCC1 Port 139 (NetBIOS) - File sharing"
                }
                2049, 111 -> {
                    // NFS
                    if (port == 2049) {
                        result = "\uD83D\uDCC1 Port 2049 (NFS) - Network file system"
                        s.close()
                    } else {
                        s.close()
                        result = "\uD83D\uDCC1 Port 111 (Portmapper) - RPC services"
                    }
                }
                135 -> {
                    s.close()
                    result = "\uD83D\uDCC1 Port 135 (MSRPC) - Windows RPC"
                }
                else -> {
                    // HTTP - check for directory listing
                    try {
                        val proto = if (port in intArrayOf(443, 8443)) "https" else "http"
                        val conn = URL("$proto://$ip:$port/").openConnection() as HttpURLConnection
                        conn.connectTimeout = 800
                        conn.readTimeout = 800
                        conn.setRequestProperty("User-Agent", "Mozilla/5.0 NetScan/1.1")
                        val code = try { conn.responseCode } catch (_: Exception) { 0 }
                        val ct = conn.getHeaderField("Content-Type") ?: ""
                        val server = conn.getHeaderField("Server") ?: ""

                        var isDirListing = false
                        var hasIndexTitle = false
                        var title = ""

                        if (code in 200..399) {
                            try {
                                val reader = BufferedReader(InputStreamReader(conn.inputStream, "UTF-8"), 1024)
                                var line: String?
                                var lineCount = 0
                                while (reader.readLine().also { line = it } != null && lineCount < 30) {
                                    val lc = (line ?: "").lowercase()
                                    // Check for directory listing signatures
                                    if (lc.contains("index of") || lc.contains("<title>")) {
                                        val m = Regex("<title[^>]*>(.*?)</title>", RegexOption.IGNORE_CASE).find(line ?: "")
                                        if (m != null) {
                                            title = m.groupValues[1].take(60).trim()
                                            hasIndexTitle = true
                                            if (title.lowercase().contains("index of")) isDirListing = true
                                        }
                                    }
                                    if (lc.contains("parent directory") || lc.contains("../") ||
                                        lc.contains("<img src=\"/icons/") || lc.contains("apache") && lc.contains("directory listing")) {
                                        isDirListing = true
                                    }
                                    lineCount++
                                }
                                reader.close()
                            } catch (_: Exception) { }
                            conn.disconnect()

                            if (isDirListing || hasIndexTitle) {
                                val parts = mutableListOf<String>()
                                parts.add("Port $port")
                                if (title.isNotEmpty() && !title.lowercase().contains("index of")) {
                                    parts.add("\"$title\"")
                                } else if (isDirListing) {
                                    parts.add("Directory listing")
                                }
                                // WebDAV detection
                                if (server.contains("Microsoft-IIS") || server.contains("Apache") ||
                                    title.lowercase().contains("webdav") || title.lowercase().contains("dav")) {
                                    parts.add("[WebDAV]")
                                }
                                if (server.isNotEmpty()) parts.add("· $server")
                                result = "\uD83D\uDCC1 ${parts.joinToString(" ")}"
                            }
                        } else {
                            conn.disconnect()
                        }
                    } catch (_: Exception) { }
                    s.close()
                }
            }

            result
        } catch (_: Exception) { null }
    }

    private fun updateSharesResults(shares: ConcurrentHashMap<String, MutableList<String>>) {
        val sb = StringBuilder()
        val sorted = shares.entries.sortedBy { it.key }
        var num = 1
        for ((ip, shareList) in sorted) {
            sb.appendLine("\uD83D\uDCC1 $num. http://$ip/")
            for (share in shareList) {
                sb.appendLine("   \u2514 $share")
            }
            sb.appendLine()
            num++
        }
        tvResults.text = sb.toString().trimStart()
        tvResults.movementMethod = LinkMovementMethod.getInstance()
        tvSummary.text = "${shares.size} host(s) with shares"
    }


    // ─── Device Discovery (all connected devices) ───
    private fun devicesScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        val targets = autoExpandTarget(target)
        val hostCount = targets.size
        AlertDialog.Builder(this)
            .setTitle("Device Discovery")
            .setMessage("Scanning all connected devices on $target\n\n~$hostCount IP(s) to check\n\nIdentifies device type by probing\ncommon ports & services.")
            .setPositiveButton("Scan") { _, _ -> runDevicesScan(target) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private data class DeviceInfo(
        val ip: String,
        val hostname: String,
        val type: String,
        val ports: String,
        val mac: String,
        val rtt: String
    )

    private val deviceProbePorts = intArrayOf(80, 443, 22, 23, 21, 445, 139, 554, 8080, 8291, 3389, 5900, 3306, 2049, 53, 161)

    private fun runDevicesScan(target: String) {
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Discovering devices...\n"
        tvSummary.text = ""
        status("Device discovery...", "#01579B", true)
        showProgress()

        Thread {
            val devices = ConcurrentHashMap<String, DeviceInfo>()
            val startTime = System.currentTimeMillis()

            try {
                val targets = autoExpandTarget(target)
                if (targets.isEmpty()) {
                    uiPost("Invalid target", "#C62828", false)
                    isScanning = false
                    return@Thread
                }

                // On local subnet, use ARP scan first
                val localIp = getWifiIp()
                val isLocal = targets.size > 1 && target.contains(localIp.substringBeforeLast("."))
                var liveHosts = targets.toSet()

                if (isLocal) {
                    uiPost("Discovering live hosts...", "#01579B", true)
                    val subnet = targets.first().substringBeforeLast(".") + "."
                    val live = arpScan(subnet)
                    if (live.isNotEmpty()) liveHosts = live
                }

                val hosts = liveHosts.toList()
                uiPost("Identifying ${hosts.size} device(s)...", "#01579B", true)

                val latch = CountDownLatch(hosts.size)
                val pool = Executors.newFixedThreadPool(30)
                val progCount = AtomicInteger(0)

                for (ip in hosts) {
                    if (!isScanning) { latch.countDown(); continue }
                    pool.execute {
                        try {
                            val info = identifyDevice(ip)
                            if (info != null) {
                                devices[ip] = info
                                ui.post { updateDevicesResults(devices) }
                            }
                        } finally {
                                latch.countDown()
                                val done = progCount.incrementAndGet()
                                ui.post { updateProgress(done, hosts.size) }
                            }
                    }
                }

                pool.shutdown()
                latch.await()
                ui.post { updateDevicesResults(devices) }

            } catch (e: Exception) {
                uiPost("Error: ${e.message}", "#C62828", false)
            }

            val elapsed = System.currentTimeMillis() - startTime
            ui.post {
                val routerCount = devices.values.count { it.type.contains("Router", ignoreCase = true) }
                val cameraCount = devices.values.count { it.type.contains("Camera", ignoreCase = true) }
                val computerCount = devices.values.count { it.type.contains("PC", ignoreCase = true) || it.type.contains("Windows", ignoreCase = true) || it.type.contains("Linux") }
                val phoneCount = devices.values.count { it.type.contains("Phone", ignoreCase = true) || it.type.contains("Android", ignoreCase = true) }
                val summary = "${devices.size} device(s) | $routerCount router(s) · $cameraCount camera(s) · $computerCount computer(s) · $phoneCount phone(s)"
                tvSummary.text = summary
                status("${devices.size} device(s) in ${elapsed / 1000}s", "#01579B", true)
                toast("${devices.size} device(s) found")
            }
            hideProgress()
            isScanning = false
        }.start()
    }

    private fun identifyDevice(ip: String): DeviceInfo? {
        var hostname = ""
        var rtt = ""
        var openPorts = mutableListOf<Pair<Int, String>>()

        // Ping & hostname
        try {
            val addr = InetAddress.getByName(ip)
            val start = System.nanoTime()
            val reachable = addr.isReachable(1000)
            if (!reachable) return null
            val ms = (System.nanoTime() - start) / 1_000_000
            if (ms < 1000) rtt = "${ms}ms"

            val hn = addr.hostName ?: ""
            if (hn != ip) hostname = hn
        } catch (_: Exception) { return null }

        // Probe essential ports
        for (port in deviceProbePorts) {
            try {
                val s = Socket()
                s.connect(InetSocketAddress(ip, port), 400)
                if (s.isConnected) {
                    val svcName = when (port) {
                        22 -> "SSH"; 23 -> "Telnet"; 21 -> "FTP"; 80 -> "HTTP"
                        443 -> "HTTPS"; 445 -> "SMB"; 139 -> "NetBIOS"
                        554 -> "RTSP"; 8080 -> "HTTP-Alt"; 8291 -> "Winbox"
                        3389 -> "RDP"; 5900 -> "VNC"; 3306 -> "MySQL"
                        2049 -> "NFS"; 53 -> "DNS"; 161 -> "SNMP"
                        else -> "P$port"
                    }
                    openPorts.add(Pair(port, svcName))
                    s.close()
                }
            } catch (_: Exception) { }
        }

        if (openPorts.isEmpty()) {
            // Host is alive but no open ports - probably a phone/tablet/IoT
            val type = guessDeviceByHostname(hostname)
            return DeviceInfo(ip, hostname, type, "alive (no open ports)", "", rtt)
        }

        // Classify device
        val type = classifyDevice(openPorts, ip, hostname)
        val portsStr = openPorts.sortedBy { it.first }.joinToString(", ") { it.second }

        return DeviceInfo(ip, hostname, type, portsStr, "", rtt)
    }

    private fun classifyDevice(ports: List<Pair<Int, String>>, ip: String, hostname: String): String {
        val portNums = ports.map { it.first }.toSet()
        val svcs = ports.map { it.second }

        // Router/Gateway - has web admin + possibly DNS/DHCP/Winbox
        if (portNums.contains(80) || portNums.contains(443) || portNums.contains(8080)) {
            if (portNums.contains(8291) || portNums.contains(53) || portNums.contains(2000)) {
                val result = try {
                    val conn = URL("http://$ip:/").openConnection() as HttpURLConnection
                    conn.connectTimeout = 500
                    val server = conn.getHeaderField("Server") ?: ""
                    conn.disconnect()
                    when {
                        server.contains("MikroTik") || server.contains("RouterOS") -> "Router (MikroTik)"
                        server.contains("TP-Link") -> "Router (TP-Link)"
                        server.contains("Tenda") -> "Router (Tenda)"
                        server.contains("GoAhead") -> "Router"
                        else -> "Router"
                    }
                } catch (_: Exception) { "Router" }
                return result
            }
        }

        // Camera - RTSP
        if (portNums.contains(554)) return "Camera (RTSP)"

        // Windows PC - SMB + RDP + NetBIOS
        if (portNums.contains(445) || portNums.contains(139)) {
            if (portNums.contains(3389)) return "Windows PC"
            if (portNums.contains(135)) return "Windows PC"
            return "Windows/Linux (SMB)"
        }

        // Linux/Unix server - SSH
        if (portNums.contains(22)) {
            if (portNums.contains(80) || portNums.contains(443)) return "Linux Server (SSH+Web)"
            if (portNums.contains(3306)) return "Database Server"
            return "Linux/Unix"
        }

        // Printer
        if (portNums.contains(631) || portNums.contains(9100) || portNums.contains(515)) return "Printer"

        // VNC
        if (portNums.contains(5900)) return "Remote Desktop (VNC)"

        // Web server only
        if (portNums.contains(80) || portNums.contains(443) || portNums.contains(8080)) {
            val result = try {
                val conn = URL("http://$ip:${if (portNums.contains(80)) 80 else portNums.first { it == 443 || it == 8080 }}/").openConnection() as HttpURLConnection
                conn.connectTimeout = 500
                val server = conn.getHeaderField("Server") ?: ""
                conn.disconnect()
                when {
                    server.contains("Apache") -> "Web Server (Apache)"
                    server.contains("nginx") -> "Web Server (nginx)"
                    server.contains("IIS") -> "Web Server (IIS)"
                    server.contains("GoAhead") -> "IoT Device"
                    else -> "Web Server"
                }
            } catch (_: Exception) { "Web Server" }
            return result
        }

        // FTP server
        if (portNums.contains(21)) return "FTP Server"

        // NFS
        if (portNums.contains(2049)) return "NAS/Storage"

        // SNMP - network device
        if (portNums.contains(161)) return "Network Device (SNMP)"

        // Telnet
        if (portNums.contains(23)) return "Legacy Device (Telnet)"

        // DNS
        if (portNums.contains(53)) return "DNS Server"

        // Only SSH
        if (portNums.size == 1 && portNums.contains(22)) return "Linux/SSH Device"

        return "Unknown Device"
    }

    private fun guessDeviceByHostname(hostname: String): String {
        val h = hostname.lowercase()
        return when {
            h.contains("phone") || h.contains("iphone") || h.contains("android") || h.contains("samsung") -> "Phone"
            h.contains("tv") || h.contains("television") || h.contains("led") -> "Smart TV"
            h.contains("printer") || h.contains("print") -> "Printer"
            h.contains("camera") || h.contains("cam") || h.contains("cctv") -> "Camera"
            h.contains("laptop") || h.contains("pc") || h.contains("desktop") || h.contains("computer") -> "PC"
            h.contains("tablet") || h.contains("ipad") -> "Tablet"
            h.contains("router") || h.contains("gateway") || h.contains("ap.") || h.contains("switch") -> "Network Device"
            h.contains("nas") || h.contains("storage") || h.contains("disk") -> "NAS"
            h.contains("iot") || h.contains("sensor") -> "IoT"
            h.contains("server") -> "Server"
            else -> "Device (no ports)"
        }
    }

    private fun updateDevicesResults(devices: ConcurrentHashMap<String, DeviceInfo>) {
        val sb = StringBuilder()
        val sorted = devices.entries.sortedBy { it.key }
        var num = 1
        for ((ip, dev) in sorted) {
            val osGuess = if (dev.hostname.isNotEmpty()) "(${dev.hostname})" else ""
            sb.appendLine("${num}. http://$ip/ $osGuess")
            sb.appendLine("   \u2514 \uD83C\uDF10 ${dev.type}")

            if (dev.rtt.isNotEmpty()) {
                sb.appendLine("     \u26A1 ${dev.rtt}")
            }
            if (dev.ports.isNotEmpty() && !dev.ports.contains("alive")) {
                sb.appendLine("     \uD83D\uDD0C $dev.ports")
            }
            sb.appendLine()
            num++
        }
        tvResults.text = sb.toString().trimStart()
        tvResults.movementMethod = LinkMovementMethod.getInstance()
        tvSummary.text = "${devices.size} device(s) found"
    }


    // ─── Full Discovery: Camera + Router + Shares ───
    private fun discoverScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        AlertDialog.Builder(this)
            .setTitle("Full Discovery")
            .setMessage("Comprehensive scan of ALL devices on $target\n\nFor each device checks:\n\uD83D\uDCF7 Camera ports (RTSP/ONVIF/Hikvision)\n\uD83C\uDF10 Router admin (HTTP/Winbox/CWMP)\n\uD83D\uDCC1 File shares (FTP/SMB/NFS/HTTP listing)\n\nAuto-expands single IP to /24 subnet.")
            .setPositiveButton("Start") { _, _ -> runDiscoverScan(target) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private val discoverPorts = intArrayOf(
        80, 443, 8080, 8443, 21, 22, 23, 445, 139, 554,
        8899, 34567, 37777, 37215, 8291, 7547, 5000, 2049,
        111, 135, 3389, 5900, 8554, 8081, 8082, 8888, 9000
    )

    private fun runDiscoverScan(target: String) {
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Full discovery...\n"
        tvSummary.text = ""
        status("Discovering...", "#BF360C", true)
        showProgress()

        Thread {
            val cameras = ConcurrentHashMap<String, MutableList<String>>()
            val routers = ConcurrentHashMap<String, MutableList<String>>()
            val shares = ConcurrentHashMap<String, MutableList<String>>()
            val startTime = System.currentTimeMillis()

            try {
                val targets = autoExpandTarget(target)
                if (targets.isEmpty()) {
                    uiPost("Invalid target", "#C62828", false)
                    isScanning = false
                    return@Thread
                }

                val localIp = getWifiIp()
                val isLocal = target.contains(localIp.substringBeforeLast("."))
                var liveHosts = targets.toSet()

                if (isLocal && targets.size > 1) {
                    uiPost("Discovering live hosts...", "#BF360C", true)
                    val subnet = targets.first().substringBeforeLast(".") + "."
                    val live = arpScan(subnet)
                    if (live.isNotEmpty()) liveHosts = live
                }

                val hosts = liveHosts.take(getMaxHosts()).toList()
                uiPost("Probing ${hosts.size} host(s)...", "#BF360C", true)

                val latch = CountDownLatch(hosts.size)
                val pool = Executors.newFixedThreadPool(30)

                for (ip in hosts) {
                    if (!isScanning) { latch.countDown(); continue }
                    pool.execute {
                        try {
                            if (!isScanning) return@execute
                            var deviceCameras = mutableListOf<String>()
                            var deviceRouters = mutableListOf<String>()
                            var deviceShares = mutableListOf<String>()

                            for (port in discoverPorts) {
                                if (!isScanning) break
                                try {
                                    val s = Socket()
                                    s.connect(InetSocketAddress(ip, port), getTimeout())
                                    if (!s.isConnected) { s.close(); continue }

                                    val isWeb = port in intArrayOf(80, 443, 8080, 8443, 8081, 8082, 8888, 9000)
                                    val isCameraPort = port in intArrayOf(554, 8899, 34567, 37777, 37215, 8554)
                                    val isRouterPort = port in intArrayOf(8291, 7547, 5000)
                                    val isSharePort = port in intArrayOf(21, 445, 139, 2049, 111, 135)

                                    // Camera detection
                                    if (isCameraPort) {
                                        val cam = probeCameraPort(ip, port)
                                        if (cam != null) deviceCamer
                val progCount = AtomicInteger(0)as.add(cam)
                                    }

                                    // Router detection
                                    if (isRouterPort) {
                                        val rtr = probeRouterPort(ip, port)
                                        if (rtr != null) deviceRouters.add(rtr)
                                    }

                                    // Share detection
                                    if (isSharePort) {
                                        val shr = probeSharePort(ip, port)
                                        if (shr != null) deviceShares.add(shr)
                                    }

                                    // HTTP probe - check for camera, router, share signatures
                                    if (isWeb) {
                                        val webResult = probeWebService(ip, port)
                                        if (webResult != null) {
                                            when (webResult.type) {
                                                "camera" -> deviceCameras.add(webResult.info)
                                                "router" -> deviceRouters.add(webResult.info)
                                                "share" -> deviceShares.add(webResult.info)
                                            }
                                        }
                                    }

                                    s.close()
                                } catch (_: Exception) { }
                            }

                            if (deviceCameras.isNotEmpty() || deviceRouters.isNotEmpty() || deviceShares.isNotEmpty()) {
                                synchronized(cameras) { if (deviceCameras.isNotEmpty()) cameras[ip] = deviceCameras }
                                synchronized(routers) { if (deviceRouters.isNotEmpty()) routers[ip] = deviceRouters }
                                synchronized(shares) { if (deviceShares.isNotEmpty()) shares[ip] = deviceShares }
                                ui.post { updateDiscoverResults(cameras, routers, shares) }
                            }
                        } finally {
                                latch.countDown()
                                val done = progCount.incrementAndGet()
                                ui.post { updateProgress(done, hosts.size) }
                            }
                    }
                }

                pool.shutdown()
                latch.await()
                ui.post { updateDiscoverResults(cameras, routers, shares) }

            } catch (e: Exception) {
                uiPost("Error: ${e.message}", "#C62828", false)
            }

            val elapsed = System.currentTimeMillis() - startTime
            ui.post {
                val summary = "\uD83D\uDCF7 ${cameras.size} camera(s)  \uD83C\uDF10 ${routers.size} router(s)  \uD83D\uDCC1 ${shares.size} share(s)  |  ${elapsed / 1000}s"
                tvSummary.text = summary
                status("${cameras.size + routers.size + shares.size} service(s) in ${elapsed / 1000}s", "#BF360C", true)
                toast("Discover complete")
            }
            hideProgress()
            isScanning = false
        }.start()
    }

    private data class WebResult(val type: String, val info: String)

    private fun probeWebService(ip: String, port: Int): WebResult? {
        return try {
            val proto = if (port in intArrayOf(443, 8443)) "https" else "http"
            val conn = URL("$proto://$ip:$port/").openConnection() as HttpURLConnection
            conn.connectTimeout = getTimeout().coerceAtMost(2000)
            conn.readTimeout = getTimeout().coerceAtMost(2000)
            conn.setRequestProperty("User-Agent", "Mozilla/5.0")
            val code = try { conn.responseCode } catch (_: Exception) { 0 }
            if (code == 0 || code == 404) { conn.disconnect(); return null }

            val server = conn.getHeaderField("Server") ?: ""
            val www = conn.getHeaderField("WWW-Authenticate") ?: ""
            val ct = conn.getHeaderField("Content-Type") ?: ""

            var title = ""
            var bodyKeywords = ""
            try {
                val reader = BufferedReader(InputStreamReader(if (code in 200..399) conn.inputStream else conn.errorStream, "UTF-8"), 512)
                var line: String?
                var lc = 0
                while (reader.readLine().also { line = it } != null && lc < 40) {
                    val m = Regex("<title[^>]*>(.*?)</title>", RegexOption.IGNORE_CASE).find(line ?: "")
                    if (m != null) { title = m.groupValues[1].take(60).trim() }
                    bodyKeywords += (line ?: "").lowercase() + " "
                    lc++
                }
                reader.close()
            } catch (_: Exception) { }
            conn.disconnect()

            val all = "$server $title $bodyKeywords $www".lowercase()

            // Camera signatures
            if (title.lowercase().contains("camera") || all.contains("hikvision") ||
                all.contains("onvif") || all.contains("rtsp") || all.contains("dahua") ||
                all.contains("webcam") || all.contains("network camera") ||
                all.contains("surveillance") || all.contains("nvr") || all.contains("dvr") ||
                title.lowercase().contains("camera") || server.contains("Camera")) {
                val mfg = guessCameraMfg(title, server, www)
                val info = "\uD83D\uDCF7 Port $port ${mfg.ifEmpty { "Camera" }}${if (title.isNotEmpty() && !title.lowercase().contains(title.lowercase())) " \"$title\"" else ""}${if (www.isNotEmpty()) " [Auth]" else ""}"
                return WebResult("camera", info)
            }

            // Router signatures
            if (port == 8291 || port == 7547 || port in intArrayOf(80, 443, 8080, 8443) &&
                (title.lowercase().contains("login") || title.lowercase().contains("admin") ||
                 title.lowercase().contains("router") || title.lowercase().contains("setup") ||
                 title.lowercase().contains("configuration") || title.lowercase().contains("management") ||
                 server.contains("MikroTik") || server.contains("RouterOS") || server.contains("TP-Link") ||
                 server.contains("Tenda") || server.contains("GoAhead") || server.contains("mini_httpd") ||
                 server.contains("thttpd") || server.contains("Boa") ||
                 all.contains("password") || all.contains("username") || all.contains("login"))) {
                val brand = identifyRouterBrand(server, title, www)
                val info = "\uD83C\uDF10 Port $port ${brand.ifEmpty { "Router" }}${if (www.isNotEmpty()) " [Auth]" else ""}${if (title.isNotEmpty() && !brand.contains(title)) " \"$title\"" else ""}"
                return WebResult("router", info)
            }

            // File share signatures
            if (bodyKeywords.contains("index of") || bodyKeywords.contains("parent directory") ||
                bodyKeywords.contains("directory listing") || bodyKeywords.contains("../") ||
                all.contains("webdav") || server.contains("WebDAV")) {
                val dirType = if (bodyKeywords.contains("index of")) "Directory listing" else "WebDAV"
                val info = "\uD83D\uDCC1 Port $port $dirType${if (server.isNotEmpty()) " [$server]" else ""}"
                return WebResult("share", info)
            }

            null
        } catch (_: Exception) { null }
    }

    private fun probeCameraPort(ip: String, port: Int): String? {
        return when (port) {
            554, 8554 -> {
                try {
                    val s = Socket()
                    s.connect(InetSocketAddress(ip, port), 500)
                    s.getOutputStream().write("OPTIONS rtsp://$ip:$port RTSP/1.0\r\nCSeq: 1\r\n\r\n".toByteArray())
                    val reader = BufferedReader(InputStreamReader(s.getInputStream(), "ISO-8859-1"))
                    val resp = reader.readLine() ?: ""
                    s.close()
                    if (resp.contains("RTSP")) "\uD83D\uDCF7 Port $port (RTSP)"
                    else null
                } catch (_: Exception) { null }
            }
            8899, 5000 -> {
                try {
                    val s = Socket()
                    s.connect(InetSocketAddress(ip, port), 500)
                    val xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
                        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">" +
                        "<s:Body><GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>" +
                        "</s:Body></s:Envelope>"
                    s.getOutputStream().write(xml.toByteArray())
                    val reader = BufferedReader(InputStreamReader(s.getInputStream(), "ISO-8859-1"))
                    val resp = StringBuilder()
                    var line: String?
                    while (reader.readLine().also { line = it } != null) resp.append(line)
                    s.close()
                    if (resp.toString().contains("ONVIF") || resp.toString().contains("Capabilities"))
                        "\uD83D\uDCF7 Port $port (ONVIF)"
                    else null
                } catch (_: Exception) { null }
            }
            34567 -> "\uD83D\uDCF7 Port 34567 (Hikvision SDK)"
            37777 -> "\uD83D\uDCF7 Port 37777 (Dahua SDK)"
            37215 -> "\uD83D\uDCF7 Port 37215 (Hikvision backdoor)"
            else -> null
        }
    }

    private fun probeRouterPort(ip: String, port: Int): String? {
        return when (port) {
            8291 -> "\uD83C\uDF10 Port 8291 (Winbox) - MikroTik"
            7547 -> "\uD83C\uDF10 Port 7547 (CWMP/TR-069)"
            5000 -> "\uD83C\uDF10 Port 5000 (UPnP)"
            else -> null
        }
    }

    private fun probeSharePort(ip: String, port: Int): String? {
        return when (port) {
            21 -> {
                try {
                    val s = Socket()
                    s.connect(InetSocketAddress(ip, 21), 500)
                    val reader = BufferedReader(InputStreamReader(s.getInputStream(), "ISO-8859-1"))
                    val banner = reader.readLine() ?: ""
                    s.close()
                    if (banner.contains("FTP") || banner.contains("220"))
                        "\uD83D\uDCC1 Port 21 (FTP) ${banner.take(40)}"
                    else null
                } catch (_: Exception) { null }
            }
            445 -> "\uD83D\uDCC1 Port 445 (SMB) - File sharing"
            139 -> "\uD83D\uDCC1 Port 139 (NetBIOS) - File sharing"
            2049 -> "\uD83D\uDCC1 Port 2049 (NFS) - File system"
            111 -> "\uD83D\uDCC1 Port 111 (Portmapper)"
            135 -> "\uD83D\uDCC1 Port 135 (MSRPC)"
            else -> null
        }
    }

    private fun updateDiscoverResults(
        cameras: ConcurrentHashMap<String, MutableList<String>>,
        routers: ConcurrentHashMap<String, MutableList<String>>,
        shares: ConcurrentHashMap<String, MutableList<String>>
    ) {
        val allIps = (cameras.keys + routers.keys + shares.keys).toSortedSet()
        val sb = StringBuilder()

        for (ip in allIps) {
            val ipLabel = "${allIps.indexOf(ip) + 1}. http://$ip/"
            sb.appendLine(ipLabel)

            cameras[ip]?.forEach { sb.appendLine("   \u2514 $it") }
            routers[ip]?.forEach { sb.appendLine("   \u2514 $it") }
            shares[ip]?.forEach { sb.appendLine("   \u2514 $it") }

            sb.appendLine()
        }

        tvResults.text = sb.toString().trimStart()
        tvResults.movementMethod = LinkMovementMethod.getInstance()
        tvSummary.text = "\uD83D\uDCF7 ${cameras.size} \uD83C\uDF10 ${routers.size} \uD83D\uDCC1 ${shares.size}  |  ${allIps.size} host(s)"
    }

    private fun uiPost(msg: String, hex: String, ok: Boolean) {
        ui.post { status(msg, hex, ok) }
    }

    private fun status(msg: String, hex: String, ok: Boolean) {
        statusText.text = msg
        statusText.setTextColor(Color.parseColor(hex))
        statusDot.setBackgroundColor(Color.parseColor(if (ok) "#2E7D32" else "#C62828"))
    }

    private fun toast(msg: String) {
        Toast.makeText(this, "  $msg  ", Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        isScanning = false
    }

}
