package com.example.networkscanner

import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
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
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var statusDot: View
    private lateinit var tvResults: TextView
    private lateinit var tvSummary: TextView
    private lateinit var cardResults: View
    private var isScanning = false

    // Thread pool for parallel scanning (max 50 concurrent)
    private var scannerPool = Executors.newFixedThreadPool(50)
    private val ui = Handler(Looper.getMainLooper())

    // Common web ports (quick scan)
    private val quickPorts = intArrayOf(80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9000, 81, 444, 8291, 2000)

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.tvStatus)
        statusDot = findViewById(R.id.dotStatus)
        tvResults = findViewById(R.id.tvResults)
        tvSummary = findViewById(R.id.tvSummary)
        cardResults = findViewById(R.id.cardResults)

        findViewById<MaterialButton>(R.id.btnQuickScan).setOnClickListener { quickScan() }
        findViewById<MaterialButton>(R.id.btnFullScan).setOnClickListener { fullScan() }
        findViewById<MaterialButton>(R.id.btnClear).setOnClickListener {
            cardResults.visibility = View.GONE
            status("Ready to scan", "#78909C", false)
        }
    }

    private fun quickScan() {
        if (isScanning) { toast("Already scanning!"); return }
        status("Quick scan: common ports...", "#E65100", true)
        runScan(quickPorts)
    }

    private fun fullScan() {
        if (isScanning) { toast("Already scanning!"); return }
        AlertDialog.Builder(this)
            .setTitle("Full Scan")
            .setMessage("Scan 200+ ports on all 254 IPs.\nTakes ~2 minutes.")
            .setPositiveButton("Start") { _, _ -> runScan(getAllPorts()) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun runScan(ports: IntArray) {
        // Ensure fresh thread pool
        if (scannerPool.isShutdown) scannerPool = Executors.newFixedThreadPool(50)
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Preparing scan...\n"
        tvSummary.text = ""
        status("Resolving network...", "#E65100", true)

        Thread {
            val startTime = System.currentTimeMillis()
            val allResults = ConcurrentHashMap<String, MutableList<String>>()
            val activeHosts = AtomicInteger(0)
            val portCount = ports.size

            try {
                // 1. Get actual WiFi IP (not 127.0.0.1)
                val localIp = getWifiIp()
                uiPost("Scanning $localIp/24...", "#E65100", true)

                val parts = localIp.split(".")
                if (parts.size != 4) {
                    uiPost("Invalid IP: $localIp", "#C62828", false)
                    isScanning = false
                    return@Thread
                }
                val subnet = "${parts[0]}.${parts[1]}.${parts[2]}."

                // 2. ARP scan first to find live hosts
                uiPost("ARP discovery...", "#E65100", true)
                val liveIps = arpScan(subnet)
                uiPost("Found ${liveIps.size} host(s) via ARP", "#2E7D32", true)

                // 3. Port scan each live host in parallel
                val scannedCount = AtomicInteger(0)
                val totalTargets = if (liveIps.isNotEmpty()) liveIps.size else 254

                for (i in 1..254) {
                    if (!isScanning) break
                    val ip = "$subnet$i"

                    // Skip if ARP didn't find it (unless ARP found nothing)
                    if (liveIps.isNotEmpty() && ip !in liveIps) continue

                    scannerPool.execute {
                        try {
                            if (!isScanning) return@execute
                            val ipServices = mutableListOf<String>()

                            for (port in ports) {
                                if (!isScanning) break
                                try {
                                    val s = Socket()
                                    s.connect(InetSocketAddress(ip, port), 200)
                                    if (!s.isConnected) { s.close(); continue }

                                    // Scan success! Now identify the service
                                    val detail = probeService(ip, port, s)
                                    synchronized(ipServices) { ipServices.add(detail) }
                                    s.close()
                                } catch (_: Exception) { }
                            }

                            if (ipServices.isNotEmpty()) {
                                allResults[ip] = ipServices
                                activeHosts.incrementAndGet()
                                val done = scannedCount.incrementAndGet()
                                val pct = (done * 100 / totalTargets)
                                uiPost("[${done}/$totalTargets] Found at $ip", "#2E7D32", true)

                                // Update results live
                                ui.post {
                                    val sb = StringBuilder()
                                    val sorted = allResults.entries.sortedBy { it.key }
                                    for ((host, svcs) in sorted) {
                                        sb.append("\n$host\n")
                                        for (svc in svcs) sb.append("  $svc\n")
                                    }
                                    tvResults.text = sb.toString().trimStart()
                                }
                            } else {
                                scannedCount.incrementAndGet()
                            }
                        } catch (_: Exception) { }
                    }
                }

                // Wait for all threads to finish
                scannerPool.shutdown()
                scannerPool.awaitTermination(5, TimeUnit.MINUTES)

            } catch (e: Exception) {
                uiPost("Error: ${e.message}", "#C62828", false)
            }

            // Final result
            val elapsed = System.currentTimeMillis() - startTime
            val summary = "\n── Done in ${elapsed / 1000}s ──  ${activeHosts.get()} host(s) found"

            ui.post {
                tvSummary.text = summary
                val sb = StringBuilder()
                val sorted = allResults.entries.sortedBy { it.key }
                for ((host, svcs) in sorted) {
                    sb.append("\n$host\n")
                    for (svc in svcs) sb.append("  $svc\n")
                }
                tvResults.text = sb.toString().trimStart()
                status("${activeHosts.get()} host(s) found", "#2E7D32", true)
                toast("Scan complete: ${activeHosts.get()} hosts")
                isScanning = false
            }
        }.start()
    }

    /** Get the actual WiFi IP address */
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
                        if (!addr.isLoopbackAddress && ip.contains(".")) {
                            return ip
                        }
                    }
                }
            }
        } catch (_: Exception) { }
        // Fallback
        return try {
            InetAddress.getLocalHost().hostAddress ?: "192.168.0.101"
        } catch (_: Exception) { "192.168.0.101" }
    }

    /** ARP scan: ping sweep to find live hosts */
    private fun arpScan(subnet: String): Set<String> {
        val live = Collections.synchronizedSet(mutableSetOf<String>())
        val pingPool = Executors.newFixedThreadPool(50)
        val pingsDone = AtomicInteger(0)

        for (i in 1..254) {
            val ip = "$subnet$i"
            pingPool.execute {
                try {
                    val addr = InetAddress.getByName(ip)
                    if (addr.isReachable(300)) {
                        synchronized(live) { live.add(ip) }
                    }
                } catch (_: Exception) { }
                pingsDone.incrementAndGet()
            }
        }
        pingPool.shutdown()
        try { pingPool.awaitTermination(15, TimeUnit.SECONDS) } catch (_: Exception) { }
        return live
    }

    /** Probe a port: try to identify the service and grab banner */
    private fun probeService(ip: String, port: Int, sock: Socket): String {
        val isWebPort = port in intArrayOf(
            80, 81, 443, 444, 3000, 4000, 5000, 5001, 7000, 7070, 7443, 7547,
            8000, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
            8090, 8180, 8222, 8243, 8280, 8443, 8444, 8530, 8531, 8649, 8800,
            8834, 8880, 8888, 8889, 8983, 9000, 9001, 9043, 9060, 9080, 9090,
            9091, 9100, 9200, 9290, 9300, 9418, 9443, 9600, 9800, 9999, 10000,
            10001, 10080, 12345, 13337, 16010, 16379, 17000, 17001, 20000, 22000,
            25565, 32400, 32764, 49154, 49155, 49156, 50000, 50100, 50200, 61616, 64738, 65535
        )
        val service = guessService(port)

        return if (isWebPort) {
            probeHttp(ip, port, service)
        } else {
            probeBanner(ip, port, sock, service)
        }
    }

    /** HTTP probe: get full response headers + title */
    private fun probeHttp(ip: String, port: Int, service: String): String {
        try {
            val protocol = if (port == 443 || port == 8443 || port == 7443 || port == 8243
                || port == 9443 || port == 4443 || port == 4343 || port == 444
                || port == 8531 || port == 8444) "https" else "http"
            val conn = URL("$protocol://$ip:$port/").openConnection() as HttpURLConnection
            conn.connectTimeout = 1500
            conn.readTimeout = 1500
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("User-Agent", "NetScan/1.0")
            conn.setRequestProperty("Accept", "text/html,*/*")

            val code = try { conn.responseCode } catch (_: Exception) { 0 }
            val msg = try { conn.responseMessage } catch (_: Exception) { "" }
            val server = conn.getHeaderField("Server") ?: ""
            val loc = conn.getHeaderField("Location") ?: ""
            val ct = conn.getHeaderField("Content-Type") ?: ""
            val wwwAuth = conn.getHeaderField("WWW-Authenticate") ?: ""

            // Try to read page title
            var title = ""
            try {
                val reader = BufferedReader(InputStreamReader(
                    if (code in 200..399) conn.inputStream else conn.errorStream, "UTF-8"
                ), 512)
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line!!.trim()
                    if (l.contains("<title", ignoreCase = true)) {
                        val m = Regex("<title[^>]*>(.*?)</title>", RegexOption.IGNORE_CASE)
                            .find(l)?.groupValues?.getOrNull(1) ?: ""
                        title = m.take(60).trim()
                        if (title.isNotEmpty()) break
                    }
                }
                reader.close()
            } catch (_: Exception) { }
            conn.disconnect()

            val parts = mutableListOf<String>()
            parts.add("Port $port ($service)")
            if (code > 0) parts.add("HTTP $code${if (msg.isNotEmpty()) " $msg" else ""}")
            if (server.isNotEmpty()) parts.add("· $server")
            if (loc.isNotEmpty() && loc.length < 70) parts.add("→ $loc")
            if (wwwAuth.isNotEmpty()) parts.add("🔒 Auth required")
            if (title.isNotEmpty()) parts.add("📄 \"$title\"")
            if (ct.isNotEmpty() && !ct.startsWith("text/html")) parts.add("[$ct]")
            return parts.joinToString(" ")

        } catch (_: Exception) {
            return "Port $port ($service) [TCP open]"
        }
    }

    /** Banner grab for non-web ports */
    private fun probeBanner(ip: String, port: Int, sock: Socket, service: String): String {
        var banner = ""
        try {
            // Try to read a banner (most services send one on connect)
            sock.soTimeout = 1000
            val reader = BufferedReader(InputStreamReader(sock.getInputStream(), "ISO-8859-1"))
            val sb = StringBuilder()
            val cbuf = CharArray(256)
            val len = reader.read(cbuf)
            if (len > 0) {
                banner = String(cbuf, 0, len).trim().take(40)
                sb.append(banner)
            }
            reader.close()
        } catch (_: Exception) { }

        return if (banner.isNotEmpty()) {
            "Port $port ($service) → \"$banner\""
        } else {
            "Port $port ($service) [open]"
        }
    }

    /** Generate all ports for full scan */
    private fun getAllPorts(): IntArray {
        val webPorts = intArrayOf(
            80, 81, 82, 88, 443, 444, 3000, 4000, 5000, 5001, 7000, 7070, 7443, 7547,
            8000, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
            8180, 8222, 8243, 8280, 8443, 8444, 8530, 8531, 8649, 8800, 8834, 8880,
            8888, 8889, 8983, 9000, 9001, 9043, 9060, 9080, 9090, 9091, 9100, 9200,
            9290, 9300, 9418, 9443, 9600, 9800, 9999, 10000, 10001, 10080, 12345,
            13337, 16010, 16379, 17000, 17001, 20000, 22000, 25565, 27017, 31337,
            32400, 32764, 49154, 49155, 49156, 50000, 50100, 50200, 61616, 64738, 65535
        )
        val otherPorts = intArrayOf(
            21, 22, 23, 53, 110, 111, 123, 135, 139, 143, 161, 389, 445, 500, 502,
            514, 546, 547, 554, 587, 623, 631, 636, 993, 995, 1080, 1194, 1433,
            1494, 1521, 1701, 1723, 1883, 1900, 2000, 2082, 2083, 2086, 2087,
            2095, 2096, 2181, 2222, 2375, 2376, 3128, 3260, 3299, 3306, 3389,
            3390, 4222, 4343, 4443, 4848, 5432, 5555, 5631, 5666, 5800, 5900,
            5901, 5984, 6000, 6001, 6379, 6646, 6666, 7777, 8291, 11211, 49152
        )
        return webPorts + otherPorts
    }

    private fun guessService(port: Int): String = when (port) {
        21 -> "FTP"; 22 -> "SSH"; 23 -> "Telnet"; 53 -> "DNS"
        80, 81, 82, 88 -> "HTTP"; 110 -> "POP3"; 111 -> "RPC"
        123 -> "NTP"; 135 -> "MSRPC"; 139 -> "NetBIOS"; 143 -> "IMAP"
        161 -> "SNMP"; 389 -> "LDAP"; 443, 444 -> "HTTPS"; 445 -> "SMB"
        500 -> "IKE"; 502 -> "Modbus"; 514 -> "Syslog"; 546, 547 -> "DHCPv6"
        554 -> "RTSP"; 587 -> "SMTP"; 623 -> "IPMI"; 631 -> "IPP"
        636 -> "LDAPS"; 993 -> "IMAPS"; 995 -> "POP3S"; 1080 -> "SOCKS"
        1194 -> "OpenVPN"; 1433 -> "MSSQL"; 1494 -> "Citrix"
        1521 -> "Oracle"; 1701 -> "L2TP"; 1723 -> "PPTP"
        1883 -> "MQTT"; 1900 -> "UPnP"; 2000 -> "BW-Test"
        2082, 2083 -> "cPanel"; 2086, 2087 -> "WHM"
        2095, 2096 -> "WebMail"; 2181 -> "ZooKeeper"; 2222 -> "SSH-Alt"
        2375, 2376 -> "Docker"; 3000 -> "Dev-Web"; 3128 -> "Squid"
        3260 -> "iSCSI"; 3299 -> "Dev-Web2"; 3306 -> "MySQL"
        3389, 3390 -> "RDP"; 4000 -> "Web-Alt"; 4222 -> "Web-Alt2"
        4343, 4443 -> "HTTPS-Alt"; 4848 -> "GlassFish"
        5000, 5001 -> "Web-Alt3"; 5432 -> "PostgreSQL"
        5555 -> "ADB"; 5631 -> "VNC"; 5666 -> "Nagios"
        5800, 5900, 5901 -> "VNC"; 5984 -> "CouchDB"
        6000, 6001 -> "X11"; 6379 -> "Redis"
        6646 -> "Web-Alt4"; 6666 -> "Web-Alt5"
        7000, 7070 -> "Web-Alt6"; 7443 -> "HTTPS-Alt2"
        7547 -> "CWMP"; 7777 -> "Web-Alt7"
        8000, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090 -> "HTTP-Alt"
        8180, 8222 -> "HTTP-Alt2"; 8243, 8280 -> "HTTP-Alt3"
        8291 -> "Winbox"; 8443, 8444 -> "HTTPS-Alt4"
        8530, 8531 -> "HTTP-Alt5"; 8649 -> "Ganglia"
        8800 -> "Web-Alt8"; 8834 -> "Nessus"
        8880, 8888, 8889 -> "HTTP-Alt6"; 8983 -> "Solr"
        9000, 9001 -> "Web-Alt9"; 9043 -> "WebSphere"
        9060, 9080 -> "HTTP-Alt7"; 9090, 9091 -> "Web-Alt10"
        9100 -> "Printer"; 9200 -> "Elasticsearch"
        9290, 9300 -> "Elastic"; 9418 -> "Git"
        9443 -> "HTTPS-Alt5"; 9600, 9800, 9999 -> "Web-Alt11"
        10000, 10001 -> "Web-Alt12"; 10080 -> "HTTP-Alt8"
        11211 -> "Memcached"; 12345 -> "Web-Alt13"
        13337 -> "Web-Alt14"; 16010, 16379 -> "Web-Alt15"
        17000, 17001 -> "Web-Alt16"; 20000, 22000 -> "Web-Alt17"
        25565 -> "Minecraft"; 27017 -> "MongoDB"
        31337 -> "BackOrifice"; 32400 -> "Plex"
        32764 -> "Router-Exp"; 49152, 49154, 49155, 49156 -> "WinRPC"
        50000 -> "Web-Alt18"; 50100, 50200 -> "Web-Alt19"
        61616 -> "Web-Alt20"; 64738 -> "Mumble"
        65535 -> "Web-Alt21"
        else -> "?"
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
        scannerPool.shutdownNow()
    }
}
