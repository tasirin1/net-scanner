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

        findViewById<MaterialButton>(R.id.btnQuick).setOnClickListener { quickScan() }
        findViewById<MaterialButton>(R.id.btnFull).setOnClickListener { fullScan() }
        findViewById<MaterialButton>(R.id.btnNmap).setOnClickListener { nmapScan() }
        // Preset chips
        findViewById<TextView>(R.id.preLocal).setOnClickListener { inputTarget.setText("192.168.0.0/24") }
        findViewById<TextView>(R.id.preRouter).setOnClickListener { inputTarget.setText("192.168.0.1") }
        findViewById<TextView>(R.id.preWan).setOnClickListener { inputTarget.setText("157.66.50.147") }
        findViewById<TextView>(R.id.preHost).setOnClickListener { inputTarget.setText("barayacell.com") }

        (findViewById<View>(R.id.btnSave) as Button).setOnClickListener { saveResults() }
    }

    // ─── Get target from input ───
    private fun getTarget(): String {
        val t = inputTarget.text?.toString()?.trim() ?: ""
        return if (t.isEmpty()) "192.168.0.0/24" else t
    }

    // ─── Quick scan ───
    private fun quickScan() {
        if (isScanning) { toast("Already scanning!"); return }
        runScan(getTarget(), quickPorts, "Quick Scan")
    }

    // ─── Full scan (all ports on a single target) ───
    private fun fullScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        // If CIDR, confirm 200+ ports on subnet is heavy
        if (target.contains("/")) {
            AlertDialog.Builder(this)
                .setTitle("Full Scan")
                .setMessage("Full scan on a subnet scans 200+ ports on all hosts.\nMay take 2-3 minutes.")
                .setPositiveButton("Start") { _, _ -> runScan(target, getAllPorts(), "Full Scan") }
                .setNegativeButton("Cancel", null)
                .show()
        } else {
            runScan(target, getAllPorts(), "Full Scan")
        }
    }

    // ─── Nmap-style scan (OS detection + version + aggressive) ───
    private fun nmapScan() {
        if (isScanning) { toast("Already scanning!"); return }
        val target = getTarget()
        AlertDialog.Builder(this)
            .setTitle("Nmap-Style Scan")
            .setMessage("Aggressive scan: version detection,\nOS fingerprint, default ports +\nbanner grabbing on all services.\nTakes ~2 minutes.")
            .setPositiveButton("Start") { _, _ -> runScan(target, getAllPorts(), "Nmap-Style") }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ─── Core scan engine ───
    private fun runScan(target: String, ports: IntArray, mode: String) {
        isScanning = true
        cardResults.visibility = View.VISIBLE
        tvResults.text = "Initializing $mode...\n"
        tvSummary.text = ""
        findViewById<View>(R.id.btnSave).visibility = View.GONE
        status("Preparing $mode...", "#E65100", true)

        Thread {
            val startTime = System.currentTimeMillis()
            val allResults = ConcurrentHashMap<String, MutableList<String>>()
            val activeHosts = AtomicInteger(0)
            val osDetected = ConcurrentHashMap<String, String>()

            try {
                // Parse target into list of IPs
                val targets = expandTarget(target)
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

                val latch = CountDownLatch(scanTargets.size)
                val scannerPool = Executors.newFixedThreadPool(Math.min(30, scanTargets.size))

                for (ip in scanTargets) {
                    if (!isScanning) { latch.countDown(); continue }
                    scannerPool.execute {
                        try {
                            if (!isScanning) return@execute
                            val ipServices = mutableListOf<String>()
                            var hasOs = false

                            for (port in ports) {
                                if (!isScanning) break
                                try {
                                    val s = Socket()
                                    s.connect(InetSocketAddress(ip, port), if (mode == "Nmap-Style") 300 else 200)
                                    if (!s.isConnected) { s.close(); continue }
                                    val detail = probeService(ip, port, s, mode)
                                    synchronized(ipServices) { ipServices.add(detail) }
                                    s.close()
                                } catch (_: Exception) { }
                            }

                            if (ipServices.isNotEmpty()) {
                                allResults[ip] = ipServices
                                activeHosts.incrementAndGet()

                                // OS fingerprint (only in Nmap mode)
                                if (mode == "Nmap-Style") {
                                    val os = guessOs(ip, ipServices)
                                    if (os.isNotEmpty()) osDetected[ip] = os
                                }

                                ui.post { updateResults(allResults, osDetected) }
                            }
                        } finally { latch.countDown() }
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
                isScanning = false
            }
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

    private fun saveResults() {
        val text = tvResults.text.toString()
        if (text.isEmpty()) { toast("Nothing to save"); return }
        try {
            val dir = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
            val file = java.io.File(dir, "NetScan_${java.text.SimpleDateFormat("yyyyMMdd_HHmmss", java.util.Locale.US).format(java.util.Date())}.txt")
            file.writeText(text)
            toast("Saved to Downloads")
        } catch (e: Exception) {
            try {
                val file = java.io.File(filesDir, "NetScan_last.txt")
                file.writeText(text)
                toast("Saved: ${file.absolutePath}")
            } catch (e2: Exception) {
                toast("Save failed: ${e2.message}")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isScanning = false
    }
}
