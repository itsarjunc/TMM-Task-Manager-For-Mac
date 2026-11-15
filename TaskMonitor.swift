import AppKit
import Darwin
import Darwin.libproc
import IOKit
import Collaboration

// MARK: - Enums
private enum Page: Int {
    case processes = 0
    case performance = 1
    case battery = 2
    case disk = 3
}

private enum PerfResource { case cpu, memory, disk, network }

private enum ProcessStatus: String {
    case running = "Running"; case sleeping = "Sleeping"
    case stopped = "Stopped"; case zombie = "Zombie"
    init(bsdStatus: UInt32) {
        switch Int32(bsdStatus) {
        case 2:  self = .running
        case 4:  self = .stopped
        case 5:  self = .zombie
        default: self = .sleeping
        }
    }
}

private enum EnergyImpact: String {
    case veryLow = "Very Low"; case low = "Low"; case medium = "Medium"
    case high = "High"; case veryHigh = "Very High"
    var color: NSColor {
        switch self {
        case .veryLow, .low: return .systemGreen
        case .medium:        return .systemOrange
        case .high, .veryHigh: return .systemRed
        }
    }
    static func from(nanojoules: Double) -> EnergyImpact {
        switch nanojoules {
        case ..<500_000:    return .veryLow
        case ..<5_000_000:  return .low
        case ..<30_000_000: return .medium
        case ..<100_000_000:return .high
        default:            return .veryHigh
        }
    }
}

// MARK: - Data Models
private struct PreviousTaskSample {
    let startTime: UInt64
    let cpuNanoseconds: UInt64
    let diskBytes: UInt64
    let energyNj: UInt64
    let wakeups: UInt64
    let sampledAt: UInt64
}

private struct PreviousNetSample {
    let sent: UInt64; let received: UInt64; let timestamp: UInt64
}

private struct RawTask: Identifiable {
    let id: pid_t
    let name: String
    let path: String
    let memoryBytes: UInt64
    let cpuPercent: Double
    let diskBytesPerSecond: Double
    let threadCount: Int
    let handleCount: Int
    let energyNjPerSecond: Double
    let wakeupRate: Double
    let status: ProcessStatus
    let startTime: UInt64
    let isProtected: Bool
    var energyImpact: EnergyImpact { .from(nanojoules: energyNjPerSecond) }
}

private struct SystemSample {
    let cpuPercent: Double
    let perCoreCPU: [Double]
    let previousCPUTicks: [UInt32]?
    let previousPerCoreTicks: [UInt32]?
    let memoryUsedBytes: UInt64
    let memoryTotalBytes: UInt64
    let memoryWiredBytes: UInt64
    let memoryCompressedBytes: UInt64
    let memoryAppBytes: UInt64
    let memoryCachedBytes: UInt64
    let memoryFreeBytes: UInt64
    let netSentBPS: Double
    let netReceivedBPS: Double
    let previousNet: PreviousNetSample?
    let diskReadBPS: Double
    let diskWriteBPS: Double
    let processCount: Int
    let totalThreadCount: Int
    let previousTasks: [pid_t: PreviousTaskSample]
}

private struct TaskRow: Identifiable {
    let task: RawTask
    let displayName: String
    let kind: String
    let icon: NSImage?
    var id: pid_t { task.id }
}

private struct BatteryData {
    let hasBattery: Bool
    let currentCapacityPercent: Int
    let isCharging: Bool
    let isPluggedIn: Bool
    let fullyCharged: Bool
    let voltageMilliVolts: Int
    let amperageMilliAmps: Int
    let wattage: Double
    let cycleCount: Int
    let designCapacityMAh: Int
    let fullChargeCapacityMAh: Int
    let healthPercent: Double
    let timeRemainingMinutes: Int
    let deviceName: String
    let serialNumber: String
    let condition: String
}

private struct DiskSMARTData {
    let model: String
    let protocolName: String
    let sizeBytes: Int64
    let isSSD: Bool
    let smartStatus: String
    let percentageUsed: Int?
    let healthRemainingPercent: Int?
    let temperatureCelsius: Double?
    let powerOnHours: Int?
    let powerCycles: Int?
    let unsafeShutdowns: Int?
    let dataUnitsWrittenTB: Double?
    let dataUnitsReadTB: Double?
    let availableSparePercent: Int?
    let mediaErrors: Int?
    let volumeTotalBytes: Int64
    let volumeFreeBytes: Int64
}

// MARK: - Process & System Reader
private enum ProcessReader {

    static func read(
        previousTasks: [pid_t: PreviousTaskSample],
        previousCPUTicks: [UInt32]?,
        previousPerCoreTicks: [UInt32]?,
        previousNet: PreviousNetSample?
    ) -> (tasks: [RawTask], sample: SystemSample) {

        let currentUID = getuid()
        let countHint = max(proc_listallpids(nil, 0), 256)
        var pids = [pid_t](repeating: 0, count: Int(countHint) + 64)
        let pidCount = pids.withUnsafeMutableBufferPointer { buf in
            proc_listallpids(buf.baseAddress, Int32(buf.count * MemoryLayout<pid_t>.stride))
        }
        let safeCount = min(max(Int(pidCount), 0), pids.count)
        let logicalCores = max(ProcessInfo.processInfo.activeProcessorCount, 1)

        var tasks: [RawTask] = []
        var nextSamples: [pid_t: PreviousTaskSample] = [:]
        tasks.reserveCapacity(safeCount)
        nextSamples.reserveCapacity(safeCount)
        var totalThreads = 0

        for pid in pids.prefix(safeCount) where pid > 1 {
            var bsd = proc_bsdinfo()
            let bsdSz = Int32(MemoryLayout<proc_bsdinfo>.size)
            guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, bsdSz) == bsdSz,
                  bsd.pbi_uid == currentUID else { continue }

            var usage = rusage_info_v6()
            let usageOK = withUnsafeMutablePointer(to: &usage) { p in
                p.withMemoryRebound(to: UnsafeMutableRawPointer?.self, capacity: 1) {
                    proc_pid_rusage(pid, RUSAGE_INFO_V6, $0)
                }
            } == 0
            guard usageOK else { continue }

            var taskInfo = proc_taskinfo()
            let taskSz = Int32(MemoryLayout<proc_taskinfo>.size)
            let gotTask = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskInfo, taskSz) == taskSz
            let threadCount = gotTask ? Int(taskInfo.pti_threadnum) : Int(bsd.pbi_nfiles > 0 ? 1 : 1)

            let fdBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            let fdSize = MemoryLayout<proc_fdinfo>.size
            let handleCount = fdBytes > 0 && fdSize > 0 ? Int(fdBytes) / fdSize : Int(bsd.pbi_nfiles)

            totalThreads += threadCount

            let now = DispatchTime.now().uptimeNanoseconds
            let startTime = UInt64(bsd.pbi_start_tvsec) &* 1_000_000 &+ UInt64(bsd.pbi_start_tvusec)
            let cpuTime  = usage.ri_user_time &+ usage.ri_system_time
            let diskTotal = usage.ri_diskio_bytesread &+ usage.ri_diskio_byteswritten
            let energy   = usage.ri_energy_nj
            let wakeups  = usage.ri_pkg_idle_wkups &+ usage.ri_interrupt_wkups

            var cpuPercent = 0.0
            var diskRate   = 0.0
            var energyRate = 0.0
            var wakeupRate = 0.0

            if let old = previousTasks[pid], old.startTime == startTime, now > old.sampledAt {
                let elapsed  = Double(now - old.sampledAt)
                let elapsedS = elapsed / 1_000_000_000
                let cpuDelta  = Double(cpuTime >= old.cpuNanoseconds ? cpuTime - old.cpuNanoseconds : 0)
                let diskDelta = Double(diskTotal >= old.diskBytes ? diskTotal - old.diskBytes : 0)
                let nrgDelta  = Double(energy >= old.energyNj ? energy - old.energyNj : 0)
                let wkDelta   = Double(wakeups >= old.wakeups ? wakeups - old.wakeups : 0)
                cpuPercent = min(100, max(0, cpuDelta / elapsed * 100 / Double(logicalCores)))
                diskRate   = max(0, diskDelta / elapsedS)
                energyRate = max(0, nrgDelta  / elapsedS)
                wakeupRate = max(0, wkDelta   / elapsedS)
            }
            nextSamples[pid] = PreviousTaskSample(
                startTime: startTime,
                cpuNanoseconds: cpuTime,
                diskBytes: diskTotal,
                energyNj: energy,
                wakeups: wakeups,
                sampledAt: now
            )

            let name  = processName(pid) ?? "Process \(pid)"
            let path  = processPath(pid) ?? ""
            let prot  = pid == getpid() || path.isEmpty || isProtectedPath(path)
            let mem   = usage.ri_phys_footprint > 0 ? usage.ri_phys_footprint : usage.ri_resident_size

            tasks.append(RawTask(
                id: pid, name: name, path: path,
                memoryBytes: mem,
                cpuPercent: cpuPercent,
                diskBytesPerSecond: diskRate,
                threadCount: threadCount,
                handleCount: handleCount,
                energyNjPerSecond: energyRate,
                wakeupRate: wakeupRate,
                status: ProcessStatus(bsdStatus: bsd.pbi_status),
                startTime: startTime,
                isProtected: prot
            ))
        }

        let (sysPercent, newCPUTicks)   = systemCPU(previous: previousCPUTicks)
        let (perCore, newPerCoreTicks)  = perCoreCPU(previous: previousPerCoreTicks)
        let mem = systemMemoryDetailed()
        let (netSent, netRecv, newNetSample) = sampleNetwork(previous: previousNet)

        let diskReadBPS  = tasks.map { $0.diskBytesPerSecond * 0.5 }.reduce(0, +)
        let diskWriteBPS = tasks.map { $0.diskBytesPerSecond * 0.5 }.reduce(0, +)

        let sample = SystemSample(
            cpuPercent: sysPercent,
            perCoreCPU: perCore,
            previousCPUTicks: newCPUTicks,
            previousPerCoreTicks: newPerCoreTicks,
            memoryUsedBytes: mem.used,
            memoryTotalBytes: mem.total,
            memoryWiredBytes: mem.wired,
            memoryCompressedBytes: mem.compressed,
            memoryAppBytes: mem.app,
            memoryCachedBytes: mem.cached,
            memoryFreeBytes: mem.free,
            netSentBPS: netSent,
            netReceivedBPS: netRecv,
            previousNet: newNetSample,
            diskReadBPS: diskReadBPS,
            diskWriteBPS: diskWriteBPS,
            processCount: tasks.count,
            totalThreadCount: totalThreads,
            previousTasks: nextSamples
        )
        return (tasks, sample)
    }

    private static func processName(_ pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 512)
        return buf.withUnsafeMutableBufferPointer {
            proc_name(pid, $0.baseAddress, UInt32($0.count)) > 0
        } ? String(cString: buf) : nil
    }

    private static func processPath(_ pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4096)
        return buf.withUnsafeMutableBufferPointer {
            proc_pidpath(pid, $0.baseAddress, UInt32($0.count)) > 0
        } ? String(cString: buf) : nil
    }

    private static func isProtectedPath(_ path: String) -> Bool {
        ["/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/Library/Apple/System/"]
            .contains(where: path.hasPrefix)
    }

    private static func systemCPU(previous: [UInt32]?) -> (Double, [UInt32]?) {
        var info = host_cpu_load_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info_data_t>.size / MemoryLayout<integer_t>.size)
        let ok = withUnsafeMutablePointer(to: &info) { p in
            p.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, $0, &count)
            }
        } == KERN_SUCCESS
        guard ok else { return (0, nil) }
        let ticks = [info.cpu_ticks.0, info.cpu_ticks.1, info.cpu_ticks.2, info.cpu_ticks.3]
        guard let prev = previous, prev.count == ticks.count else { return (0, ticks) }
        let delta = zip(ticks, prev).map { UInt64($0 &- $1) }
        let total = delta.reduce(UInt64(0), &+)
        guard total > 0 else { return (0, ticks) }
        let busy = delta[0] &+ delta[1] &+ delta[3]
        return (min(100, Double(busy) / Double(total) * 100), ticks)
    }

    private static func perCoreCPU(previous: [UInt32]?) -> ([Double], [UInt32]?) {
        var coreCount: natural_t = 0
        var infoPtr: processor_info_array_t? = nil
        var infoCount: mach_msg_type_number_t = 0
        guard host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO, &coreCount, &infoPtr, &infoCount) == KERN_SUCCESS,
              let info = infoPtr else { return ([], nil) }
        defer {
            let sz = vm_size_t(infoCount) * vm_size_t(MemoryLayout<integer_t>.size)
            vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: info)), sz)
        }
        let states = Int(CPU_STATE_MAX)
        let n = Int(coreCount)
        let current = (0..<n * states).map { UInt32(bitPattern: info[$0]) }
        var pct = [Double](repeating: 0, count: n)
        if let prev = previous, prev.count == n * states {
            for i in 0..<n {
                let b = i * states
                let u = UInt64(current[b + Int(CPU_STATE_USER)]   &- prev[b + Int(CPU_STATE_USER)])
                let s = UInt64(current[b + Int(CPU_STATE_SYSTEM)] &- prev[b + Int(CPU_STATE_SYSTEM)])
                let d = UInt64(current[b + Int(CPU_STATE_IDLE)]   &- prev[b + Int(CPU_STATE_IDLE)])
                let k = UInt64(current[b + Int(CPU_STATE_NICE)]   &- prev[b + Int(CPU_STATE_NICE)])
                let total = u + s + d + k
                pct[i] = total > 0 ? min(100, Double(u + s + k) / Double(total) * 100) : 0
            }
        }
        return (pct, current)
    }

    private static func systemMemoryDetailed() -> (used: UInt64, total: UInt64, wired: UInt64,
                                                    compressed: UInt64, app: UInt64, cached: UInt64, free: UInt64) {
        var info = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let ok = withUnsafeMutablePointer(to: &info) { p in
            p.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        } == KERN_SUCCESS
        let total = ProcessInfo.processInfo.physicalMemory
        guard ok else { return (0, total, 0, 0, 0, 0, 0) }
        var pg: vm_size_t = 0
        host_page_size(mach_host_self(), &pg)
        let p = UInt64(pg)
        let wired      = UInt64(info.wire_count) * p
        let active     = UInt64(info.active_count) * p
        let inactive   = UInt64(info.inactive_count) * p
        let compressed = UInt64(info.compressor_page_count) * p
        let purgeable  = UInt64(info.purgeable_count) * p
        let speculative = UInt64(info.speculative_count) * p
        let free       = UInt64(info.free_count) * p + speculative
        let app    = wired + (active > purgeable ? active - purgeable : 0)
        let cached = purgeable + inactive
        let available = min(total, free + inactive + speculative + purgeable)
        let used = total > available ? total - available : 0
        return (used, total, wired, compressed, app, cached, free)
    }

    private static func sampleNetwork(previous: PreviousNetSample?) -> (sent: Double, recv: Double, PreviousNetSample) {
        var addrs: UnsafeMutablePointer<ifaddrs>? = nil
        let now = DispatchTime.now().uptimeNanoseconds
        var totalSent: UInt64 = 0
        var totalRecv: UInt64 = 0
        if getifaddrs(&addrs) == 0, let start = addrs {
            defer { freeifaddrs(start) }
            var ptr: UnsafeMutablePointer<ifaddrs>? = start
            while let cur = ptr {
                let ifa = cur.pointee
                let isLoopback = ifa.ifa_flags & UInt32(IFF_LOOPBACK) != 0
                if !isLoopback,
                   let sa = ifa.ifa_addr, sa.pointee.sa_family == UInt8(AF_LINK),
                   let raw = ifa.ifa_data {
                    let st = raw.assumingMemoryBound(to: if_data.self).pointee
                    totalSent += UInt64(st.ifi_obytes)
                    totalRecv += UInt64(st.ifi_ibytes)
                }
                ptr = ifa.ifa_next
            }
        }
        let snap = PreviousNetSample(sent: totalSent, received: totalRecv, timestamp: now)
        var sentBPS = 0.0; var recvBPS = 0.0
        if let prev = previous, now > prev.timestamp {
            let elapsed = Double(now - prev.timestamp) / 1e9
            if totalSent >= prev.sent { sentBPS = Double(totalSent - prev.sent) / elapsed }
            if totalRecv >= prev.received { recvBPS = Double(totalRecv - prev.received) / elapsed }
        }
        return (sentBPS, recvBPS, snap)
    }

    static func pCoreCount() -> Int {
        var v: Int32 = 0; var sz = MemoryLayout<Int32>.size
        sysctlbyname("hw.perflevel0.physicalcpu", &v, &sz, nil, 0)
        return Int(v)
    }
    static func eCoreCount() -> Int {
        var v: Int32 = 0; var sz = MemoryLayout<Int32>.size
        sysctlbyname("hw.perflevel1.physicalcpu", &v, &sz, nil, 0)
        return Int(v)
    }
    static func chipName() -> String {
        var size = 0
        sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
        if size > 1 {
            var buf = [CChar](repeating: 0, count: size)
            sysctlbyname("machdep.cpu.brand_string", &buf, &size, nil, 0)
            let s = String(cString: buf)
            if !s.isEmpty { return s }
        }
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var buf2 = [CChar](repeating: 0, count: max(size, 1))
        sysctlbyname("hw.model", &buf2, &size, nil, 0)
        let model = String(cString: buf2)
        return model.isEmpty ? "Apple Silicon" : "Apple \(model)"
    }

    // Battery Diagnostics Reader
    static func readBattery() -> BatteryData {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("AppleSmartBattery"))
        guard service != 0 else {
            return BatteryData(
                hasBattery: false, currentCapacityPercent: 0, isCharging: false,
                isPluggedIn: true, fullyCharged: false, voltageMilliVolts: 0,
                amperageMilliAmps: 0, wattage: 0, cycleCount: 0, designCapacityMAh: 0,
                fullChargeCapacityMAh: 0, healthPercent: 100, timeRemainingMinutes: -1,
                deviceName: "N/A (Desktop Mac)", serialNumber: "N/A", condition: "Connected to AC"
            )
        }
        defer { IOObjectRelease(service) }
        var props: Unmanaged<CFMutableDictionary>?
        guard IORegistryEntryCreateCFProperties(service, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS,
              let dict = props?.takeRetainedValue() as? [String: Any] else {
            return BatteryData(
                hasBattery: true, currentCapacityPercent: 0, isCharging: false,
                isPluggedIn: false, fullyCharged: false, voltageMilliVolts: 0,
                amperageMilliAmps: 0, wattage: 0, cycleCount: 0, designCapacityMAh: 0,
                fullChargeCapacityMAh: 0, healthPercent: 100, timeRemainingMinutes: -1,
                deviceName: "Apple Battery", serialNumber: "Unknown", condition: "Normal"
            )
        }

        let curCap = (dict["CurrentCapacity"] as? NSNumber)?.intValue ?? 0
        let isCharging = (dict["IsCharging"] as? NSNumber)?.boolValue ?? false
        let isPlugged = (dict["ExternalConnected"] as? NSNumber)?.boolValue ?? false
        let fullyCharged = (dict["FullyCharged"] as? NSNumber)?.boolValue ?? false
        let voltage = (dict["Voltage"] as? NSNumber)?.intValue ?? 0
        let amp = (dict["Amperage"] as? NSNumber)?.intValue ?? (dict["InstantAmperage"] as? NSNumber)?.intValue ?? 0
        let cycles = (dict["CycleCount"] as? NSNumber)?.intValue ?? 0
        let serial = dict["Serial"] as? String ?? "N/A"
        let dev = dict["DeviceName"] as? String ?? "Apple Battery"
        let timeRem = (dict["TimeRemaining"] as? NSNumber)?.intValue ?? -1

        var designCap = 0
        var fullCap = 0
        if let bData = dict["BatteryData"] as? [String: Any] {
            designCap = (bData["DesignCapacity"] as? NSNumber)?.intValue ?? 0
            fullCap = (bData["FullChargeCapacity"] as? NSNumber)?.intValue ?? 0
        }
        let health = designCap > 0 && fullCap > 0 ? (Double(fullCap) / Double(designCap)) * 100.0 : 100.0
        let watts = abs(Double(voltage) * Double(amp)) / 1_000_000.0

        let condition = health < 80 ? "Service Recommended" : "Normal"

        return BatteryData(
            hasBattery: true,
            currentCapacityPercent: curCap,
            isCharging: isCharging,
            isPluggedIn: isPlugged,
            fullyCharged: fullyCharged,
            voltageMilliVolts: voltage,
            amperageMilliAmps: amp,
            wattage: watts,
            cycleCount: cycles,
            designCapacityMAh: designCap,
            fullChargeCapacityMAh: fullCap,
            healthPercent: health,
            timeRemainingMinutes: timeRem,
            deviceName: dev,
            serialNumber: serial,
            condition: condition
        )
    }

    // Disk & S.M.A.R.T. Reader
    static func readDiskSMART() -> DiskSMARTData {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/diskutil")
        p.arguments = ["info", "-plist", "disk0"]
        let pipe = Pipe()
        p.standardOutput = pipe
        try? p.run()
        p.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let plist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]) ?? [:]

        let model = plist["MediaName"] as? String ?? plist["DeviceNode"] as? String ?? "Apple SSD"
        let proto = plist["BusProtocol"] as? String ?? "Apple Fabric / NVMe"
        let size = (plist["Size"] as? NSNumber)?.int64Value ?? 0
        let isSSD = (plist["SolidState"] as? NSNumber)?.boolValue ?? true
        let smartStatus = plist["SMARTStatus"] as? String ?? "Verified"

        var pctUsed: Int? = nil
        var tempC: Double? = nil
        var pOnHours: Int? = nil
        var pCycles: Int? = nil
        var unsafeShut: Int? = nil
        var writtenTB: Double? = nil
        var readTB: Double? = nil
        var spare: Int? = nil
        var mediaErrors: Int? = nil

        if let smart = plist["SMARTDeviceSpecificKeysMayVaryNotGuaranteed"] as? [String: Any] {
            if let pu = smart["PERCENTAGE_USED"] as? NSNumber { pctUsed = pu.intValue }
            if let tk = smart["TEMPERATURE"] as? NSNumber { tempC = tk.doubleValue - 273.15 }
            if let poh = smart["POWER_ON_HOURS_0"] as? NSNumber { pOnHours = poh.intValue }
            if let pc = smart["POWER_CYCLES_0"] as? NSNumber { pCycles = pc.intValue }
            if let us = smart["UNSAFE_SHUTDOWNS_0"] as? NSNumber { unsafeShut = us.intValue }
            if let sp = smart["AVAILABLE_SPARE"] as? NSNumber { spare = sp.intValue }
            if let me = smart["MEDIA_ERRORS_0"] as? NSNumber { mediaErrors = me.intValue }
            if let duw = smart["DATA_UNITS_WRITTEN_0"] as? NSNumber {
                writtenTB = (duw.doubleValue * 512_000.0) / 1_000_000_000_000.0
            }
            if let dur = smart["DATA_UNITS_READ_0"] as? NSNumber {
                readTB = (dur.doubleValue * 512_000.0) / 1_000_000_000_000.0
            }
        }

        var totalSpace: Int64 = 0
        var freeSpace: Int64 = 0
        if let attrs = try? FileManager.default.attributesOfFileSystem(forPath: "/") {
            totalSpace = (attrs[.systemSize] as? NSNumber)?.int64Value ?? 0
            freeSpace = (attrs[.systemFreeSize] as? NSNumber)?.int64Value ?? 0
        }

        let healthRemaining = pctUsed.map { max(0, 100 - $0) }

        return DiskSMARTData(
            model: model,
            protocolName: proto,
            sizeBytes: size,
            isSSD: isSSD,
            smartStatus: smartStatus,
            percentageUsed: pctUsed,
            healthRemainingPercent: healthRemaining,
            temperatureCelsius: tempC,
            powerOnHours: pOnHours,
            powerCycles: pCycles,
            unsafeShutdowns: unsafeShut,
            dataUnitsWrittenTB: writtenTB,
            dataUnitsReadTB: readTB,
            availableSparePercent: spare,
            mediaErrors: mediaErrors,
            volumeTotalBytes: totalSpace,
            volumeFreeBytes: freeSpace
        )
    }
}

// MARK: - App Entry Point
@main private struct TaskMonitorApp {
    static var appDelegate: AppDelegate?
    static func main() {
        let app = NSApplication.shared
        let del = AppDelegate()
        appDelegate = del
        app.delegate = del
        app.setActivationPolicy(.regular)
        app.run()
    }
}

private final class AppDelegate: NSObject, NSApplicationDelegate {
    private var ctrl: TaskMonitorController?
    func applicationDidFinishLaunching(_ n: Notification) {
        ctrl = TaskMonitorController()
        ctrl?.showWindow()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        ctrl?.showWindow()
        return true
    }
}

// MARK: - macOS Settings-Style Sidebar Item
private final class SettingsSidebarItem: NSView {
    private let itemTag: Int
    override var tag: Int { return itemTag }
    let title: String
    var onClick: (() -> Void)?

    private let iconBox = NSView()
    private let iconView = NSImageView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let bgView = NSView()

    var isSelected: Bool = false {
        didSet { updateState() }
    }

    private var isHovered: Bool = false
    private var isPressed: Bool = false
    private var trackingArea: NSTrackingArea?

    private var iconBoxLeadingC: NSLayoutConstraint?
    private var iconBoxCenterX: NSLayoutConstraint?

    init(title: String, symbol: String, color: NSColor, tag: Int, onClick: (() -> Void)? = nil) {
        self.title = title
        self.itemTag = tag
        self.onClick = onClick
        super.init(frame: .zero)

        wantsLayer = true
        translatesAutoresizingMaskIntoConstraints = false

        bgView.wantsLayer = true
        bgView.layer?.cornerRadius = 8
        bgView.translatesAutoresizingMaskIntoConstraints = false
        addSubview(bgView)

        iconBox.wantsLayer = true
        iconBox.layer?.cornerRadius = 6.5
        iconBox.layer?.backgroundColor = color.cgColor
        iconBox.translatesAutoresizingMaskIntoConstraints = false

        iconView.imageScaling = .scaleProportionallyDown
        if let sym = NSImage(systemSymbolName: symbol, accessibilityDescription: title) {
            let config = NSImage.SymbolConfiguration(pointSize: 13, weight: .semibold)
            iconView.image = sym.withSymbolConfiguration(config)
        }
        iconView.contentTintColor = .white
        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconBox.addSubview(iconView)

        titleLabel.stringValue = title
        titleLabel.font = .systemFont(ofSize: 13, weight: .medium)
        titleLabel.textColor = .labelColor
        titleLabel.lineBreakMode = .byTruncatingTail
        titleLabel.isSelectable = false
        titleLabel.refusesFirstResponder = true
        titleLabel.translatesAutoresizingMaskIntoConstraints = false

        addSubview(iconBox)
        addSubview(titleLabel)

        let lead = iconBox.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 6)
        let cx = iconBox.centerXAnchor.constraint(equalTo: centerXAnchor)
        cx.priority = .defaultLow
        iconBoxLeadingC = lead
        iconBoxCenterX = cx

        NSLayoutConstraint.activate([
            bgView.leadingAnchor.constraint(equalTo: leadingAnchor),
            bgView.trailingAnchor.constraint(equalTo: trailingAnchor),
            bgView.topAnchor.constraint(equalTo: topAnchor),
            bgView.bottomAnchor.constraint(equalTo: bottomAnchor),

            lead,
            iconBox.centerYAnchor.constraint(equalTo: centerYAnchor),
            iconBox.widthAnchor.constraint(equalToConstant: 26),
            iconBox.heightAnchor.constraint(equalToConstant: 26),

            iconView.centerXAnchor.constraint(equalTo: iconBox.centerXAnchor),
            iconView.centerYAnchor.constraint(equalTo: iconBox.centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 16),
            iconView.heightAnchor.constraint(equalToConstant: 16),

            titleLabel.leadingAnchor.constraint(equalTo: iconBox.trailingAnchor, constant: 10),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -8),
            titleLabel.centerYAnchor.constraint(equalTo: centerYAnchor),

            heightAnchor.constraint(equalToConstant: 36)
        ])

        updateState()
    }
    required init?(coder: NSCoder) { fatalError() }

    override var mouseDownCanMoveWindow: Bool { false }
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    override func hitTest(_ point: NSPoint) -> NSView? {
        let localPoint = convert(point, from: superview)
        guard bounds.contains(localPoint) else { return nil }
        return self
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let ta = trackingArea { removeTrackingArea(ta) }
        let ta = NSTrackingArea(rect: bounds, options: [.mouseEnteredAndExited, .activeInActiveApp, .inVisibleRect], owner: self, userInfo: nil)
        addTrackingArea(ta)
        trackingArea = ta
    }

    override func mouseEntered(with event: NSEvent) {
        isHovered = true
        updateState()
    }

    override func mouseExited(with event: NSEvent) {
        isHovered = false
        isPressed = false
        updateState()
    }

    override func mouseDown(with event: NSEvent) {
        isPressed = true
        updateState()
    }

    override func mouseUp(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        let inside = bounds.contains(pt)
        isPressed = false
        updateState()
        if inside {
            triggerClick()
        }
    }

    func triggerClick() {
        onClick?()
    }

    // Accessibility support (VoiceOver & System Events click)
    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .button }
    override func accessibilityLabel() -> String? { title }
    override func accessibilityPerformPress() -> Bool {
        triggerClick()
        return true
    }

    func setCompact(_ compact: Bool) {
        titleLabel.isHidden = compact
        if compact {
            iconBoxLeadingC?.isActive = false
            iconBoxCenterX?.isActive = true
        } else {
            iconBoxCenterX?.isActive = false
            iconBoxLeadingC?.isActive = true
        }
    }

    private func updateState() {
        if isSelected {
            bgView.layer?.backgroundColor = isPressed
                ? NSColor.controlAccentColor.blended(withFraction: 0.15, of: .black)?.cgColor ?? NSColor.controlAccentColor.cgColor
                : NSColor.controlAccentColor.cgColor
            titleLabel.textColor = .white
            titleLabel.font = .systemFont(ofSize: 13, weight: .semibold)
        } else if isPressed {
            bgView.layer?.backgroundColor = NSColor.labelColor.withAlphaComponent(0.12).cgColor
            titleLabel.textColor = .labelColor
            titleLabel.font = .systemFont(ofSize: 13, weight: .medium)
        } else if isHovered {
            bgView.layer?.backgroundColor = NSColor.labelColor.withAlphaComponent(0.08).cgColor
            titleLabel.textColor = .labelColor
            titleLabel.font = .systemFont(ofSize: 13, weight: .medium)
        } else {
            bgView.layer?.backgroundColor = NSColor.clear.cgColor
            titleLabel.textColor = .labelColor
            titleLabel.font = .systemFont(ofSize: 13, weight: .medium)
        }
    }
}

// MARK: - macOS Settings-Style Top Navigation (< | >)
private final class SettingsTopNavView: NSView {
    let segControl: NSSegmentedControl

    init(target: AnyObject?, action: Selector?) {
        let leftImg = NSImage(systemSymbolName: "chevron.left", accessibilityDescription: "Back") ?? NSImage()
        let rightImg = NSImage(systemSymbolName: "chevron.right", accessibilityDescription: "Forward") ?? NSImage()
        let config = NSImage.SymbolConfiguration(pointSize: 11, weight: .bold)

        segControl = NSSegmentedControl(
            images: [leftImg.withSymbolConfiguration(config) ?? leftImg,
                     rightImg.withSymbolConfiguration(config) ?? rightImg],
            trackingMode: .momentary,
            target: target,
            action: action
        )
        segControl.segmentStyle = .capsule
        segControl.setWidth(28, forSegment: 0)
        segControl.setWidth(28, forSegment: 1)
        segControl.translatesAutoresizingMaskIntoConstraints = false

        super.init(frame: .zero)
        translatesAutoresizingMaskIntoConstraints = false
        addSubview(segControl)

        NSLayoutConstraint.activate([
            segControl.leadingAnchor.constraint(equalTo: leadingAnchor),
            segControl.centerYAnchor.constraint(equalTo: centerYAnchor),
            segControl.heightAnchor.constraint(equalToConstant: 24),
            heightAnchor.constraint(equalToConstant: 32)
        ])
    }
    required init?(coder: NSCoder) { fatalError() }

    func update(canGoBack: Bool, canGoForward: Bool) {
        segControl.setEnabled(canGoBack, forSegment: 0)
        segControl.setEnabled(canGoForward, forSegment: 1)
    }
}

// MARK: - macOS Settings-Style Hero Header Card
private final class SettingsHeroCard: NSView {
    private let iconBox = NSView()
    private let iconView = NSImageView()
    private let titleLabel = NSTextField(labelWithString: "")
    private let subtitleLabel = NSTextField(wrappingLabelWithString: "")

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        layer?.cornerRadius = 14
        layer?.borderWidth = 1
        layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.2).cgColor
        layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.35).cgColor
        translatesAutoresizingMaskIntoConstraints = false

        iconBox.wantsLayer = true
        iconBox.layer?.cornerRadius = 14
        iconBox.layer?.borderWidth = 1
        iconBox.layer?.borderColor = NSColor.white.withAlphaComponent(0.18).cgColor
        iconBox.layer?.masksToBounds = true
        iconBox.translatesAutoresizingMaskIntoConstraints = false

        iconView.imageScaling = .scaleProportionallyDown
        iconView.contentTintColor = .white
        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconBox.addSubview(iconView)

        titleLabel.font = .systemFont(ofSize: 22, weight: .bold)
        titleLabel.textColor = .labelColor
        titleLabel.alignment = .center
        titleLabel.lineBreakMode = .byTruncatingTail
        titleLabel.translatesAutoresizingMaskIntoConstraints = false

        subtitleLabel.font = .systemFont(ofSize: 12.5, weight: .regular)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.alignment = .center
        subtitleLabel.maximumNumberOfLines = 2
        subtitleLabel.translatesAutoresizingMaskIntoConstraints = false

        addSubview(iconBox)
        addSubview(titleLabel)
        addSubview(subtitleLabel)

        NSLayoutConstraint.activate([
            iconBox.topAnchor.constraint(equalTo: topAnchor, constant: 18),
            iconBox.centerXAnchor.constraint(equalTo: centerXAnchor),
            iconBox.widthAnchor.constraint(equalToConstant: 56),
            iconBox.heightAnchor.constraint(equalToConstant: 56),

            iconView.centerXAnchor.constraint(equalTo: iconBox.centerXAnchor),
            iconView.centerYAnchor.constraint(equalTo: iconBox.centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 30),
            iconView.heightAnchor.constraint(equalToConstant: 30),

            titleLabel.topAnchor.constraint(equalTo: iconBox.bottomAnchor, constant: 10),
            titleLabel.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),

            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            subtitleLabel.centerXAnchor.constraint(equalTo: centerXAnchor),
            subtitleLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 560),
            subtitleLabel.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 20),
            subtitleLabel.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -20),
            subtitleLabel.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -18),
        ])
    }
    required init?(coder: NSCoder) { fatalError() }

    func configure(title: String, subtitle: String, symbol: String, color: NSColor) {
        titleLabel.stringValue = title
        subtitleLabel.stringValue = subtitle
        iconBox.layer?.backgroundColor = color.cgColor
        if let img = NSImage(systemSymbolName: symbol, accessibilityDescription: title) {
            let config = NSImage.SymbolConfiguration(pointSize: 26, weight: .medium)
            iconView.image = img.withSymbolConfiguration(config)
        }
    }
}

// MARK: - Main Controller
private final class TaskMonitorController: NSObject,
        NSTableViewDataSource, NSTableViewDelegate,
        NSSearchFieldDelegate, NSWindowDelegate, NSMenuDelegate {

    // Window
    private let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 1200, height: 780),
        styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
        backing: .buffered, defer: false
    )

    // Layout roots
    private let rootView        = NSView()
    private let sidebar         = NSView()
    private let sidebarContent  = NSView()
    private let content         = NSView()

    // Sidebar controls
    private var sidebarItems: [SettingsSidebarItem] = []
    private var sidebarStack: NSStackView?
    private var sectionLabel: NSTextField?
    private var footerLabel: NSTextField?
    private var sidebarWidthC:   NSLayoutConstraint?
    private var sidebarLeadingC: NSLayoutConstraint?
    private var sidebarTrailingC:NSLayoutConstraint?
    private var sidebarTopC:     NSLayoutConstraint?

    // Content header & Navigation (macOS Settings style)
    private lazy var topNavView = SettingsTopNavView(target: self, action: #selector(navBackForward(_:)))
    private let heroCard = SettingsHeroCard()
    private var navHistory: [Page] = [.processes]
    private var navHistoryIndex: Int = 0
    private var contentLeadingC: [NSLayoutConstraint] = []
    private var contentTrailingC:[NSLayoutConstraint] = []

    // ── Processes page ──────────────────────────────────────────────────
    private let actionGlassHost    = NSView()
    private let actionGlassContent = NSView()
    private let searchField        = NSSearchField()
    private let endTaskButton      = NSButton(title: "End Task", target: nil, action: nil)
    private let refreshButton      = NSButton(title: "Refresh",  target: nil, action: nil)
    private var searchWidthC:  NSLayoutConstraint?

    private let processScrollView  = NSScrollView()
    private let processTable       = NSTableView()
    private let statusBar          = NSTextField(labelWithString: "")
    private var tableColumns: [String: NSTableColumn] = [:]

    // ── Performance page ────────────────────────────────────────────────
    private let perfPageView        = NSView()
    private let perfNavHost         = NSView()
    private let perfNavContent      = NSView()
    private let perfNavStack        = NSStackView()
    private let perfDetailHost      = NSView()
    private let perfDetailContent   = NSView()
    private var selectedResource: PerfResource = .cpu

    private var navCards: [PerfResource: PerfNavCard] = [:]
    private var cpuDetailView:  CPUDetailView?
    private var memDetailView:  MemDetailView?
    private var diskDetailView: DiskDetailView?
    private var netDetailView:  NetDetailView?

    // ── Battery page ────────────────────────────────────────────────────
    private let batteryPageView = BatteryPageView()

    // ── Disk & SMART page ───────────────────────────────────────────────
    private let diskPageView = DiskSMARTPageView()

    // State
    private var page: Page = .processes
    private var allTasks: [RawTask] = []
    private var rows: [TaskRow] = []
    private var appRows: [TaskRow] = []; private var bgRows: [TaskRow] = []
    private var displayedRows: [TaskRow] = []
    private var appMap: [pid_t: NSRunningApplication] = [:]
    private var iconCache: [String: NSImage] = [:]

    private var sample = SystemSample(
        cpuPercent: 0, perCoreCPU: [],
        previousCPUTicks: nil, previousPerCoreTicks: nil,
        memoryUsedBytes: 0, memoryTotalBytes: ProcessInfo.processInfo.physicalMemory,
        memoryWiredBytes: 0, memoryCompressedBytes: 0, memoryAppBytes: 0,
        memoryCachedBytes: 0, memoryFreeBytes: 0,
        netSentBPS: 0, netReceivedBPS: 0, previousNet: nil,
        diskReadBPS: 0, diskWriteBPS: 0,
        processCount: 0, totalThreadCount: 0,
        previousTasks: [:]
    )

    // History (60 × 2s = 2 min)
    private var cpuHistory:   [Double] = []
    private var perCoreHistory: [[Double]] = []
    private var memHistory:   [Double] = []
    private var diskRdHistory:[Double] = []
    private var diskWrHistory:[Double] = []
    private var netSentHistory:[Double] = []
    private var netRecvHistory:[Double] = []

    private var timer: Timer?
    private var isRefreshing = false
    private var sortKey = "cpu"; private var sortAscending = false

    override init() {
        super.init()
    }

    // MARK: showWindow
    func showWindow() {
        if window.contentView == nil || window.contentView !== rootView {
            buildMainMenu()
            buildWindow()
            window.delegate = self
            window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        }

        let screen = NSScreen.main ?? NSScreen.screens.first
        let vf = screen?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        let targetWidth = min(1200, max(750, vf.width - 60))
        let targetHeight = min(780, max(480, vf.height - 60))
        let targetSize = NSSize(width: targetWidth, height: targetHeight)

        window.minSize = NSSize(width: 640, height: 440)
        let x = vf.origin.x + (vf.width - targetSize.width) / 2
        let y = vf.origin.y + (vf.height - targetSize.height) / 2
        window.setFrame(NSRect(x: x, y: y, width: targetSize.width, height: targetSize.height), display: true)

        window.makeKeyAndOrderFront(nil)
        window.orderFrontRegardless()
        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
        NSRunningApplication.current.activate(options: .activateAllWindows)

        window.contentView?.layoutSubtreeIfNeeded()
        updateAdaptiveLayout(for: window.frame.size)
        refreshTasks()
        refreshDiskSMART()
        if timer == nil {
            timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
                guard let self, self.window.isVisible else { return }
                self.refreshTasks()
            }
        }
    }

    // MARK: - Build Window
    private func buildWindow() {
        window.title = "Task Monitor"
        window.isReleasedWhenClosed = false
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.isMovableByWindowBackground = true
        rootView.wantsLayer = true
        rootView.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        rootView.autoresizingMask = [.width, .height]
        window.contentView = rootView

        content.translatesAutoresizingMaskIntoConstraints = false
        sidebar.translatesAutoresizingMaskIntoConstraints = false
        sidebarContent.translatesAutoresizingMaskIntoConstraints = false

        rootView.addSubview(sidebar)
        installGlass(in: sidebar, content: sidebarContent, radius: 0, material: .sidebar)

        let divider = NSView()
        divider.wantsLayer = true
        divider.layer?.backgroundColor = NSColor.separatorColor.withAlphaComponent(0.25).cgColor
        divider.translatesAutoresizingMaskIntoConstraints = false
        sidebar.addSubview(divider)

        rootView.addSubview(content)

        let sw = sidebar.widthAnchor.constraint(equalToConstant: 236)
        sidebarWidthC = sw
        NSLayoutConstraint.activate([
            sidebar.leadingAnchor.constraint(equalTo: rootView.leadingAnchor),
            sidebar.topAnchor.constraint(equalTo: rootView.topAnchor),
            sidebar.bottomAnchor.constraint(equalTo: rootView.bottomAnchor),
            sw,

            divider.trailingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            divider.topAnchor.constraint(equalTo: sidebar.topAnchor),
            divider.bottomAnchor.constraint(equalTo: sidebar.bottomAnchor),
            divider.widthAnchor.constraint(equalToConstant: 1),

            content.leadingAnchor.constraint(equalTo: sidebar.trailingAnchor),
            content.trailingAnchor.constraint(equalTo: rootView.trailingAnchor),
            content.topAnchor.constraint(equalTo: rootView.topAnchor),
            content.bottomAnchor.constraint(equalTo: rootView.bottomAnchor),
        ])
        buildSidebar()
        buildContent()
    }

    private func installGlass(in host: NSView, content gc: NSView, radius: CGFloat, material: NSVisualEffectView.Material) {
        gc.translatesAutoresizingMaskIntoConstraints = false
        let bg: NSView
        if #available(macOS 27.0, *), material != .sidebar {
            let g = NSGlassEffectView(); g.style = .regular; g.effectIsInteractive = true
            g.cornerRadius = radius; g.contentView = gc; bg = g
        } else if #available(macOS 26.0, *), material != .sidebar {
            let g = NSGlassEffectView(); g.style = .regular
            g.cornerRadius = radius; g.contentView = gc; bg = g
        } else {
            let v = NSVisualEffectView(); v.material = material
            v.blendingMode = .behindWindow; v.state = .active
            v.wantsLayer = true
            if radius > 0 {
                v.layer?.cornerRadius = radius
                v.layer?.masksToBounds = true
            }
            v.addSubview(gc)
            NSLayoutConstraint.activate([
                gc.leadingAnchor.constraint(equalTo: v.leadingAnchor),
                gc.trailingAnchor.constraint(equalTo: v.trailingAnchor),
                gc.topAnchor.constraint(equalTo: v.topAnchor),
                gc.bottomAnchor.constraint(equalTo: v.bottomAnchor)
            ])
            bg = v
        }
        bg.translatesAutoresizingMaskIntoConstraints = false
        host.addSubview(bg)
        NSLayoutConstraint.activate([
            bg.leadingAnchor.constraint(equalTo: host.leadingAnchor),
            bg.trailingAnchor.constraint(equalTo: host.trailingAnchor),
            bg.topAnchor.constraint(equalTo: host.topAnchor),
            bg.bottomAnchor.constraint(equalTo: host.bottomAnchor)
        ])
    }

    // MARK: - Menu
    private func buildMainMenu() {
        let mm = NSMenu()
        let ai = NSMenuItem(); let am = NSMenu(title: "Task Monitor")
        am.addItem(NSMenuItem(title: "About Task Monitor", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: ""))
        am.addItem(.separator())
        am.addItem(NSMenuItem(title: "Quit Task Monitor", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        ai.submenu = am; mm.addItem(ai)

        let vi = NSMenuItem(); let vm = NSMenu(title: "View")
        let m1 = NSMenuItem(title: "Processes", action: #selector(menuSelectPage(_:)), keyEquivalent: "1"); m1.tag = 0; vm.addItem(m1)
        let m2 = NSMenuItem(title: "Performance", action: #selector(menuSelectPage(_:)), keyEquivalent: "2"); m2.tag = 1; vm.addItem(m2)
        let m3 = NSMenuItem(title: "Battery", action: #selector(menuSelectPage(_:)), keyEquivalent: "3"); m3.tag = 2; vm.addItem(m3)
        let m4 = NSMenuItem(title: "Disk & Storage", action: #selector(menuSelectPage(_:)), keyEquivalent: "4"); m4.tag = 3; vm.addItem(m4)
        vm.addItem(.separator())
        vm.addItem(NSMenuItem(title: "Back", action: #selector(menuNavBack), keyEquivalent: "["))
        vm.addItem(NSMenuItem(title: "Forward", action: #selector(menuNavForward), keyEquivalent: "]"))
        vm.addItem(.separator())
        vm.addItem(NSMenuItem(title: "Refresh", action: #selector(refreshButtonPressed), keyEquivalent: "r"))
        vi.submenu = vm; mm.addItem(vi)

        let wi = NSMenuItem(); let wm = NSMenu(title: "Window")
        wm.addItem(NSMenuItem(title: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m"))
        wi.submenu = wm; mm.addItem(wi)
        NSApp.mainMenu = mm
    }

    // MARK: - Sidebar (macOS Settings Style)
    private func buildSidebar() {
        let stack = NSStackView(); stack.orientation = .vertical
        stack.alignment = .leading; stack.spacing = 4
        stack.translatesAutoresizingMaskIntoConstraints = false
        sidebarStack = stack; sidebarContent.addSubview(stack)

        let top = stack.topAnchor.constraint(equalTo: sidebarContent.topAnchor, constant: 52)
        sidebarTopC = top
        let lead = stack.leadingAnchor.constraint(equalTo: sidebarContent.leadingAnchor, constant: 10)
        sidebarLeadingC = lead
        let trail = stack.trailingAnchor.constraint(equalTo: sidebarContent.trailingAnchor, constant: -10)
        sidebarTrailingC = trail
        NSLayoutConstraint.activate([top, lead, trail])

        let sec = NSTextField(labelWithString: "MONITOR")
        sec.font = .systemFont(ofSize: 10, weight: .bold); sec.textColor = .tertiaryLabelColor
        sectionLabel = sec; stack.addArrangedSubview(sec)

        // Sidebar Items (macOS Settings colorful squircle rows)
        let procs = SettingsSidebarItem(title: "Processes",      symbol: "list.bullet.rectangle.portrait", color: .systemBlue,   tag: 0) { [weak self] in
            self?.navigateTo(page: .processes, addToHistory: true)
        }
        let perf  = SettingsSidebarItem(title: "Performance",    symbol: "cpu",                           color: .systemPurple, tag: 1) { [weak self] in
            self?.navigateTo(page: .performance, addToHistory: true)
        }
        let batt  = SettingsSidebarItem(title: "Battery",        symbol: "battery.100percent.bolt",       color: .systemGreen,  tag: 2) { [weak self] in
            self?.navigateTo(page: .battery, addToHistory: true)
        }
        let disk  = SettingsSidebarItem(title: "Disk & Storage", symbol: "internaldrive",                 color: .systemGray,   tag: 3) { [weak self] in
            self?.navigateTo(page: .disk, addToHistory: true)
        }

        sidebarItems = [procs, perf, batt, disk]
        for item in sidebarItems {
            stack.addArrangedSubview(item)
            item.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
        }
        selectSidebarItem(tag: 0)

        let foot = NSTextField(wrappingLabelWithString: "Live — every 2 s")
        foot.font = .systemFont(ofSize: 11); foot.textColor = .tertiaryLabelColor
        foot.translatesAutoresizingMaskIntoConstraints = false
        footerLabel = foot; sidebarContent.addSubview(foot)
        NSLayoutConstraint.activate([
            foot.leadingAnchor.constraint(equalTo: sidebarContent.leadingAnchor, constant: 16),
            foot.bottomAnchor.constraint(equalTo: sidebarContent.bottomAnchor, constant: -16)
        ])
    }

    @objc private func sidebarItemClicked(_ sender: SettingsSidebarItem) {
        guard let p = Page(rawValue: sender.tag) else { return }
        navigateTo(page: p, addToHistory: true)
    }

    private func selectSidebarItem(tag: Int) {
        for item in sidebarItems {
            item.isSelected = item.tag == tag
        }
    }

    // MARK: - Build Content Area (macOS Settings Style)
    private func buildContent() {
        content.addSubview(topNavView)
        content.addSubview(heroCard)

        buildProcessesPage()
        buildPerformancePage()
        buildBatteryPage()
        buildDiskPage()

        perfPageView.isHidden = true
        batteryPageView.isHidden = true
        diskPageView.isHidden = true

        let tnl = topNavView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 32)
        let hl = heroCard.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 32)
        let hr = heroCard.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -32)
        let al = actionGlassHost.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 32)
        let at = actionGlassHost.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -32)
        let tbl = processScrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 32)
        let tbr = processScrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -32)
        let pl = perfPageView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 32)
        let pr = perfPageView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -32)
        let bl = batteryPageView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 32)
        let br = batteryPageView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -32)
        let dl = diskPageView.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 32)
        let dr = diskPageView.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -32)

        contentLeadingC  = [tnl, hl, al, tbl, pl, bl, dl]
        contentTrailingC = [hr, at, tbr, pr, br, dr]

        let sw = searchField.widthAnchor.constraint(equalToConstant: 220); searchWidthC = sw
        NSLayoutConstraint.activate([
            tnl,
            topNavView.topAnchor.constraint(equalTo: content.topAnchor, constant: 14),

            hl, hr,
            heroCard.topAnchor.constraint(equalTo: topNavView.bottomAnchor, constant: 10),

            al, at,
            actionGlassHost.topAnchor.constraint(equalTo: heroCard.bottomAnchor, constant: 14),
            actionGlassHost.heightAnchor.constraint(equalToConstant: 52),
            searchField.leadingAnchor.constraint(equalTo: actionGlassContent.leadingAnchor, constant: 12),
            searchField.trailingAnchor.constraint(lessThanOrEqualTo: endTaskButton.leadingAnchor, constant: -10),
            searchField.centerYAnchor.constraint(equalTo: actionGlassContent.centerYAnchor), sw,
            endTaskButton.trailingAnchor.constraint(equalTo: refreshButton.leadingAnchor, constant: -8),
            endTaskButton.centerYAnchor.constraint(equalTo: actionGlassContent.centerYAnchor),
            refreshButton.trailingAnchor.constraint(equalTo: actionGlassContent.trailingAnchor, constant: -10),
            refreshButton.centerYAnchor.constraint(equalTo: actionGlassContent.centerYAnchor),

            tbl, tbr,
            processScrollView.topAnchor.constraint(equalTo: actionGlassHost.bottomAnchor, constant: 10),
            processScrollView.bottomAnchor.constraint(equalTo: statusBar.topAnchor, constant: -6),

            statusBar.leadingAnchor.constraint(equalTo: processScrollView.leadingAnchor),
            statusBar.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -32),
            statusBar.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -14),

            pl, pr,
            perfPageView.topAnchor.constraint(equalTo: heroCard.bottomAnchor, constant: 14),
            perfPageView.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),

            bl, br,
            batteryPageView.topAnchor.constraint(equalTo: heroCard.bottomAnchor, constant: 14),
            batteryPageView.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),

            dl, dr,
            diskPageView.topAnchor.constraint(equalTo: heroCard.bottomAnchor, constant: 14),
            diskPageView.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
        ])

        heroCard.configure(
            title: "Processes",
            subtitle: "Manage running applications, background daemons, and system resource allocation.",
            symbol: "list.bullet.rectangle.portrait",
            color: .systemBlue
        )
    }

    // MARK: - Processes Page
    private func buildProcessesPage() {
        searchField.placeholderString = "Search processes"
        searchField.delegate = self; searchField.sendsSearchStringImmediately = true
        searchField.translatesAutoresizingMaskIntoConstraints = false
        actionGlassContent.translatesAutoresizingMaskIntoConstraints = false
        actionGlassContent.addSubview(searchField)

        endTaskButton.image = NSImage(systemSymbolName: "stop.fill", accessibilityDescription: nil)
        endTaskButton.imagePosition = .imageLeading; endTaskButton.bezelStyle = .rounded
        endTaskButton.contentTintColor = .systemRed; endTaskButton.target = self
        endTaskButton.action = #selector(endSelectedTask); endTaskButton.isEnabled = false
        endTaskButton.translatesAutoresizingMaskIntoConstraints = false; endTaskButton.toolTip = "End Task (⌫)"
        actionGlassContent.addSubview(endTaskButton)

        refreshButton.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: nil)
        refreshButton.bezelStyle = .texturedRounded; refreshButton.target = self
        refreshButton.action = #selector(refreshButtonPressed)
        refreshButton.translatesAutoresizingMaskIntoConstraints = false; refreshButton.toolTip = "Refresh (⌘R)"
        actionGlassContent.addSubview(refreshButton)
        actionGlassHost.translatesAutoresizingMaskIntoConstraints = false
        installGlass(in: actionGlassHost, content: actionGlassContent, radius: 16, material: .hudWindow)
        content.addSubview(actionGlassHost)

        configureTable()
        processScrollView.documentView = processTable
        processScrollView.hasVerticalScroller = true
        processScrollView.drawsBackground = false; processScrollView.borderType = .noBorder
        processScrollView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(processScrollView)

        statusBar.font = .systemFont(ofSize: 11); statusBar.textColor = .tertiaryLabelColor
        statusBar.lineBreakMode = .byTruncatingTail
        statusBar.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(statusBar)

        NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] ev in
            guard let self else { return ev }
            let cmd = ev.modifierFlags.contains(.command)
            let ch  = ev.charactersIgnoringModifiers
            if cmd && ch == "r" { self.refreshTasks(); return nil }
            if cmd && ch == "f" { self.window.makeFirstResponder(self.searchField); return nil }
            if cmd && ch == "1" { self.navigateTo(page: .processes, addToHistory: true); return nil }
            if cmd && ch == "2" { self.navigateTo(page: .performance, addToHistory: true); return nil }
            if cmd && ch == "3" { self.navigateTo(page: .battery, addToHistory: true); return nil }
            if cmd && ch == "4" { self.navigateTo(page: .disk, addToHistory: true); return nil }
            if cmd && ch == "[" { self.navBack(); return nil }
            if cmd && ch == "]" { self.navForward(); return nil }

            let isEditingSearch: Bool = {
                if let fr = self.window.firstResponder {
                    if fr === self.searchField { return true }
                    if let editor = fr as? NSTextView, editor.delegate === self.searchField { return true }
                }
                return false
            }()

            if !isEditingSearch && (ev.keyCode == 51 || ev.keyCode == 117) {
                if !self.processTable.selectedRowIndexes.isEmpty {
                    let force = ev.modifierFlags.contains(.option) || ev.modifierFlags.contains(.command)
                    self.killSelectedTasksDirectly(force: force)
                    return nil
                }
            }
            return ev
        }
    }

    private func configureTable() {
        processTable.delegate = self; processTable.dataSource = self
        processTable.usesAlternatingRowBackgroundColors = true
        processTable.rowHeight = 34
        processTable.selectionHighlightStyle = .regular
        processTable.allowsMultipleSelection = true
        processTable.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        processTable.gridStyleMask = []; processTable.style = .inset

        addCol("name",    "Name",          240, 160, true)
        addCol("status",  "Status",         80,  60, true)
        addCol("cpu",     "CPU",            72,  56, false)
        addCol("memory",  "Memory",        100,  78, false)
        addCol("disk",    "Disk",           92,  70, false)
        addCol("energy",  "Energy Impact",  96,  70, false)
        addCol("threads", "Threads",        64,  52, false)
        addCol("handles", "Handles",        70,  52, false)
        addCol("pid",     "PID",            60,  48, true)

        processTable.sortDescriptors = [NSSortDescriptor(key: "cpu", ascending: false)]

        let menu = NSMenu(); menu.delegate = self; processTable.menu = menu
    }
    private func addCol(_ id: String, _ title: String, _ w: CGFloat, _ min: CGFloat, _ asc: Bool) {
        let c = NSTableColumn(identifier: .init(id))
        c.title = title; c.width = w; c.minWidth = min
        c.sortDescriptorPrototype = NSSortDescriptor(key: id, ascending: asc)
        processTable.addTableColumn(c); tableColumns[id] = c
    }

    // MARK: - Performance Page (WTM-style)
    private func buildPerformancePage() {
        perfPageView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(perfPageView)

        perfNavContent.translatesAutoresizingMaskIntoConstraints = false
        perfNavStack.orientation = .vertical; perfNavStack.alignment = .leading
        perfNavStack.spacing = 8; perfNavStack.translatesAutoresizingMaskIntoConstraints = false
        perfNavContent.addSubview(perfNavStack)
        NSLayoutConstraint.activate([
            perfNavStack.topAnchor.constraint(equalTo: perfNavContent.topAnchor, constant: 14),
            perfNavStack.leadingAnchor.constraint(equalTo: perfNavContent.leadingAnchor, constant: 10),
            perfNavStack.trailingAnchor.constraint(equalTo: perfNavContent.trailingAnchor, constant: -10),
        ])
        perfNavHost.translatesAutoresizingMaskIntoConstraints = false
        installGlass(in: perfNavHost, content: perfNavContent, radius: 18, material: .sidebar)
        perfPageView.addSubview(perfNavHost)

        perfDetailContent.translatesAutoresizingMaskIntoConstraints = false
        perfDetailHost.translatesAutoresizingMaskIntoConstraints = false
        installGlass(in: perfDetailHost, content: perfDetailContent, radius: 18, material: .contentBackground)
        perfPageView.addSubview(perfDetailHost)

        NSLayoutConstraint.activate([
            perfNavHost.leadingAnchor.constraint(equalTo: perfPageView.leadingAnchor),
            perfNavHost.topAnchor.constraint(equalTo: perfPageView.topAnchor),
            perfNavHost.bottomAnchor.constraint(equalTo: perfPageView.bottomAnchor),
            perfNavHost.widthAnchor.constraint(equalToConstant: 190),
            perfDetailHost.leadingAnchor.constraint(equalTo: perfNavHost.trailingAnchor, constant: 12),
            perfDetailHost.trailingAnchor.constraint(equalTo: perfPageView.trailingAnchor),
            perfDetailHost.topAnchor.constraint(equalTo: perfPageView.topAnchor),
            perfDetailHost.bottomAnchor.constraint(equalTo: perfPageView.bottomAnchor),
        ])

        for resource in [PerfResource.cpu, .memory, .disk, .network] {
            let card = PerfNavCard(resource: resource, target: self, action: #selector(selectPerfResource(_:)))
            card.translatesAutoresizingMaskIntoConstraints = false
            perfNavStack.addArrangedSubview(card)
            card.widthAnchor.constraint(equalTo: perfNavStack.widthAnchor).isActive = true
            navCards[resource] = card
        }
        navCards[.cpu]?.isSelected = true

        let cpu  = CPUDetailView();  cpu.translatesAutoresizingMaskIntoConstraints = false
        let mem  = MemDetailView();  mem.translatesAutoresizingMaskIntoConstraints = false
        let disk = DiskDetailView(); disk.translatesAutoresizingMaskIntoConstraints = false
        let net  = NetDetailView();  net.translatesAutoresizingMaskIntoConstraints = false
        cpuDetailView = cpu; memDetailView = mem; diskDetailView = disk; netDetailView = net

        for v in [cpu as NSView, mem, disk, net] {
            perfDetailContent.addSubview(v)
            NSLayoutConstraint.activate([
                v.leadingAnchor.constraint(equalTo: perfDetailContent.leadingAnchor),
                v.trailingAnchor.constraint(equalTo: perfDetailContent.trailingAnchor),
                v.topAnchor.constraint(equalTo: perfDetailContent.topAnchor),
                v.bottomAnchor.constraint(equalTo: perfDetailContent.bottomAnchor),
            ])
            v.isHidden = true
        }
        cpu.isHidden = false
    }

    // MARK: - Battery Page
    private func buildBatteryPage() {
        batteryPageView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(batteryPageView)
    }

    // MARK: - Disk & SMART Page
    private func buildDiskPage() {
        diskPageView.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(diskPageView)
    }

    @objc private func selectPerfResource(_ sender: PerfNavCard) {
        selectedResource = sender.resource
        for (r, card) in navCards { card.isSelected = r == selectedResource }
        cpuDetailView?.isHidden  = selectedResource != .cpu
        memDetailView?.isHidden  = selectedResource != .memory
        diskDetailView?.isHidden = selectedResource != .disk
        netDetailView?.isHidden  = selectedResource != .network
    }

    // MARK: - Page Switch & Navigation (macOS Settings Style)
    private func navigateTo(page p: Page, addToHistory: Bool) {
        page = p
        selectSidebarItem(tag: p.rawValue)

        if addToHistory {
            if navHistoryIndex < navHistory.count - 1 {
                navHistory.removeSubrange((navHistoryIndex + 1)...)
            }
            if navHistory.last != p {
                navHistory.append(p)
                navHistoryIndex = navHistory.count - 1
            }
        }
        topNavView.update(canGoBack: navHistoryIndex > 0, canGoForward: navHistoryIndex < navHistory.count - 1)

        switch page {
        case .processes:
            heroCard.configure(
                title: "Processes",
                subtitle: "Manage running applications, background daemons, and system resource allocation.",
                symbol: "list.bullet.rectangle.portrait",
                color: .systemBlue
            )
        case .performance:
            heroCard.configure(
                title: "Performance",
                subtitle: "Live processor utilization, memory distribution, disk throughput, and network telemetry.",
                symbol: "cpu",
                color: .systemPurple
            )
        case .battery:
            heroCard.configure(
                title: "Battery",
                subtitle: "Real-time state of charge, health metrics, power flow, and electrical diagnostics.",
                symbol: "battery.100percent.bolt",
                color: .systemGreen
            )
        case .disk:
            heroCard.configure(
                title: "Disk & S.M.A.R.T.",
                subtitle: "Solid-state drive health, NVMe S.M.A.R.T. telemetry, and volume capacity.",
                symbol: "internaldrive",
                color: .systemGray
            )
            refreshDiskSMART()
        }

        let isProc = page == .processes
        actionGlassHost.isHidden = !isProc
        processScrollView.isHidden = !isProc
        statusBar.isHidden = !isProc
        perfPageView.isHidden = page != .performance
        batteryPageView.isHidden = page != .battery
        diskPageView.isHidden = page != .disk

        updateAdaptiveLayout(for: window.frame.size)
    }

    func navBack() {
        if navHistoryIndex > 0 {
            navHistoryIndex -= 1
            navigateTo(page: navHistory[navHistoryIndex], addToHistory: false)
        }
    }

    func navForward() {
        if navHistoryIndex < navHistory.count - 1 {
            navHistoryIndex += 1
            navigateTo(page: navHistory[navHistoryIndex], addToHistory: false)
        }
    }

    @objc private func menuSelectPage(_ sender: NSMenuItem) {
        guard let p = Page(rawValue: sender.tag) else { return }
        navigateTo(page: p, addToHistory: true)
    }

    @objc private func menuNavBack() { navBack() }
    @objc private func menuNavForward() { navForward() }

    @objc private func navBackForward(_ sender: NSSegmentedControl) {
        if sender.selectedSegment == 0 {
            navBack()
        } else if sender.selectedSegment == 1 {
            navForward()
        }
    }

    // MARK: - Data Refresh
    @objc private func refreshButtonPressed() {
        refreshTasks()
        if page == .disk { refreshDiskSMART() }
    }

    private func refreshTasks() {
        guard !isRefreshing else { return }
        isRefreshing = true
        let old = sample
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let (tasks, newSample) = ProcessReader.read(
                previousTasks: old.previousTasks,
                previousCPUTicks: old.previousCPUTicks,
                previousPerCoreTicks: old.previousPerCoreTicks,
                previousNet: old.previousNet
            )
            let battery = ProcessReader.readBattery()

            DispatchQueue.main.async {
                guard let self else { return }
                self.allTasks = tasks
                self.sample = newSample
                self.appMap = Dictionary(
                    NSWorkspace.shared.runningApplications.map { ($0.processIdentifier, $0) },
                    uniquingKeysWith: { first, _ in first }
                )
                self.updateRows()
                self.updatePerformance()
                self.batteryPageView.update(battery: battery)
                self.isRefreshing = false
            }
        }
    }

    private func refreshDiskSMART() {
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let smart = ProcessReader.readDiskSMART()
            DispatchQueue.main.async {
                self?.diskPageView.update(data: smart)
            }
        }
    }

    private func updateRows() {
        rows = allTasks.map { task in
            let app = appMap[task.id]
            let name = app?.localizedName ?? task.name
            let kind = app == nil ? "Background" : "App"
            return TaskRow(task: task, displayName: name, kind: kind, icon: iconFor(task: task, app: app))
        }
        applyFilterAndSort()
        let total = displayedRows.count
        let prots = displayedRows.filter { $0.task.isProtected }.count
        statusBar.stringValue = "\(total) processes  ·  \(appRows.count) apps  ·  \(bgRows.count) background  ·  \(prots) protected  ·  \(sample.totalThreadCount) threads"
    }

    private func iconFor(task: RawTask, app: NSRunningApplication?) -> NSImage? {
        let cacheKey = !task.path.isEmpty ? task.path : "\(task.name)-\(task.id)"
        if let c = iconCache[cacheKey] { return c }

        var img: NSImage?

        // 1. NSRunningApplication.icon (Highest accuracy for GUI apps)
        if let appIcon = app?.icon {
            img = appIcon
        }

        // 2. Check if executable path is part of an .app bundle
        if img == nil, !task.path.isEmpty {
            var url = URL(fileURLWithPath: task.path)
            var foundBundles: [URL] = []
            while url.path != "/" && url.pathComponents.count > 1 {
                if url.pathExtension == "app" {
                    foundBundles.append(url)
                }
                url.deleteLastPathComponent()
            }
            if let mainBundle = foundBundles.last {
                img = NSWorkspace.shared.icon(forFile: mainBundle.path)
            }
        }

        // 3. System categories
        if img == nil {
            if task.path.contains("/System/") || task.path.contains("/Library/Apple/") {
                img = NSImage(systemSymbolName: "apple.logo", accessibilityDescription: nil)
            } else if task.path.contains("/usr/libexec/") || task.path.contains("/sbin/") || task.path.contains("/Library/") {
                img = NSImage(systemSymbolName: "gearshape.2", accessibilityDescription: nil)
            } else if task.path.contains("/bin/") || task.path.contains("/usr/bin/") || task.path.contains("/opt/homebrew/") {
                img = NSImage(systemSymbolName: "terminal", accessibilityDescription: nil)
            }
        }

        // 4. File fallback
        if img == nil, !task.path.isEmpty, FileManager.default.fileExists(atPath: task.path) {
            img = NSWorkspace.shared.icon(forFile: task.path)
        }

        if img == nil {
            img = NSImage(systemSymbolName: "gearshape", accessibilityDescription: nil)
        }

        if let validImg = img {
            let resized = validImg.copy() as! NSImage
            resized.size = NSSize(width: 18, height: 18)
            iconCache[cacheKey] = resized
            return resized
        }
        return nil
    }

    private func updatePerformance() {
        let memPct = sample.memoryTotalBytes == 0 ? 0.0
            : Double(sample.memoryUsedBytes) / Double(sample.memoryTotalBytes) * 100

        func push(_ arr: inout [Double], _ v: Double) {
            arr.append(v); if arr.count > 60 { arr.removeFirst(arr.count - 60) }
        }
        push(&cpuHistory,    sample.cpuPercent)
        push(&memHistory,    memPct)
        push(&diskRdHistory, sample.diskReadBPS / 1_048_576)
        push(&diskWrHistory, sample.diskWriteBPS / 1_048_576)
        push(&netSentHistory, sample.netSentBPS / 131_072)
        push(&netRecvHistory, sample.netReceivedBPS / 131_072)

        // Track per-core history
        if perCoreHistory.count != sample.perCoreCPU.count {
            perCoreHistory = sample.perCoreCPU.map { [$0] }
        } else {
            for i in 0..<sample.perCoreCPU.count {
                perCoreHistory[i].append(sample.perCoreCPU[i])
                if perCoreHistory[i].count > 60 {
                    perCoreHistory[i].removeFirst(perCoreHistory[i].count - 60)
                }
            }
        }

        let gb = Double(1_073_741_824)
        let totalGB = Double(sample.memoryTotalBytes) / gb
        let usedGB  = Double(sample.memoryUsedBytes) / gb

        let p = ProcessInfo.processInfo
        let uptime = p.systemUptime
        let uph = Int(uptime / 3600); let upm = Int(uptime / 60) % 60; let ups = Int(uptime) % 60

        cpuDetailView?.update(
            cpuPct: sample.cpuPercent,
            history: cpuHistory,
            perCore: sample.perCoreCPU,
            perCoreHistory: perCoreHistory,
            processes: sample.processCount,
            threads: sample.totalThreadCount,
            uptime: String(format: "%d:%02d:%02d", uph, upm, ups)
        )
        memDetailView?.update(
            usedBytes: sample.memoryUsedBytes,
            totalBytes: sample.memoryTotalBytes,
            wiredBytes: sample.memoryWiredBytes,
            compressedBytes: sample.memoryCompressedBytes,
            appBytes: sample.memoryAppBytes,
            cachedBytes: sample.memoryCachedBytes,
            freeBytes: sample.memoryFreeBytes,
            history: memHistory
        )
        diskDetailView?.update(
            readBPS: sample.diskReadBPS,
            writeBPS: sample.diskWriteBPS,
            readHistory: diskRdHistory,
            writeHistory: diskWrHistory
        )
        netDetailView?.update(
            sentBPS: sample.netSentBPS,
            recvBPS: sample.netReceivedBPS,
            sentHistory: netSentHistory,
            recvHistory: netRecvHistory
        )

        navCards[.cpu]?.setValue(String(format: "%.0f%%", sample.cpuPercent), history: cpuHistory, max: 100)
        navCards[.memory]?.setValue(String(format: "%.1f / %.0f GB", usedGB, totalGB), history: memHistory, max: 100)
        navCards[.disk]?.setValue(formatRate(sample.diskReadBPS + sample.diskWriteBPS), history: diskRdHistory, max: nil)
        navCards[.network]?.setValue(formatRate(sample.netSentBPS + sample.netReceivedBPS), history: netRecvHistory, max: nil)
    }

    // MARK: - Filter & Sort
    private func applyFilterAndSort() {
        let selectedPIDs: Set<pid_t> = Set(processTable.selectedRowIndexes.compactMap { idx in
            displayedRows.indices.contains(idx) ? displayedRows[idx].id : nil
        })

        let q = searchField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var visible = rows.filter { r in
            q.isEmpty || r.displayName.lowercased().contains(q)
                || r.task.name.lowercased().contains(q)
                || String(r.id).contains(q)
        }
        visible.sort { l, r in
            switch sortKey {
            case "name":    return sortAscending ? l.displayName.localizedStandardCompare(r.displayName) == .orderedAscending
                                                 : l.displayName.localizedStandardCompare(r.displayName) == .orderedDescending
            case "status":  return sortAscending ? l.task.status.rawValue < r.task.status.rawValue
                                                 : l.task.status.rawValue > r.task.status.rawValue
            case "cpu":     return sortAscending ? l.task.cpuPercent < r.task.cpuPercent : l.task.cpuPercent > r.task.cpuPercent
            case "disk":    return sortAscending ? l.task.diskBytesPerSecond < r.task.diskBytesPerSecond : l.task.diskBytesPerSecond > r.task.diskBytesPerSecond
            case "energy":  return sortAscending ? l.task.energyNjPerSecond < r.task.energyNjPerSecond : l.task.energyNjPerSecond > r.task.energyNjPerSecond
            case "threads": return sortAscending ? l.task.threadCount < r.task.threadCount : l.task.threadCount > r.task.threadCount
            case "handles": return sortAscending ? l.task.handleCount < r.task.handleCount : l.task.handleCount > r.task.handleCount
            case "pid":     return sortAscending ? l.id < r.id : l.id > r.id
            default:        return sortAscending ? l.task.memoryBytes < r.task.memoryBytes : l.task.memoryBytes > r.task.memoryBytes
            }
        }
        appRows = visible.filter { $0.kind == "App" }
        bgRows  = visible.filter { $0.kind != "App" }
        displayedRows = visible
        processTable.reloadData()

        // Restore persistent selection across auto-refreshes
        if !selectedPIDs.isEmpty {
            var restoredIndexes = IndexSet()
            for (idx, row) in displayedRows.enumerated() {
                if selectedPIDs.contains(row.id) {
                    restoredIndexes.insert(idx)
                }
            }
            processTable.selectRowIndexes(restoredIndexes, byExtendingSelection: false)
        }
        updateEndTaskButtonState()
    }

    func controlTextDidChange(_ n: Notification) {
        applyFilterAndSort()
    }

    // MARK: - TableView DataSource
    func numberOfRows(in tableView: NSTableView) -> Int { displayedRows.count }

    func tableView(_ tv: NSTableView, viewFor col: NSTableColumn?, row: Int) -> NSView? {
        guard displayedRows.indices.contains(row), let id = col?.identifier.rawValue else { return nil }
        let item = displayedRows[row]

        if id == "name" {
            let cid = NSUserInterfaceItemIdentifier("NameCell")
            let cell = (tv.makeView(withIdentifier: cid, owner: nil) as? ProcessNameCell) ?? {
                let c = ProcessNameCell(); c.identifier = cid; return c
            }()
            cell.configure(name: item.displayName, icon: item.icon, isProtected: item.task.isProtected, kind: item.kind)
            return cell
        }

        let cid = NSUserInterfaceItemIdentifier("TextCell-\(id)")
        let cell: NSTableCellView
        if let r = tv.makeView(withIdentifier: cid, owner: nil) as? NSTableCellView {
            cell = r
        } else {
            cell = NSTableCellView(); cell.identifier = cid
            let tf = NSTextField(labelWithString: "")
            tf.font = id == "status" || id == "energy"
                ? .systemFont(ofSize: 11.5)
                : .monospacedDigitSystemFont(ofSize: 11.5, weight: .regular)
            tf.lineBreakMode = .byTruncatingTail
            tf.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(tf); cell.textField = tf
            NSLayoutConstraint.activate([
                tf.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
                tf.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
                tf.centerYAnchor.constraint(equalTo: cell.centerYAnchor)])
        }
        let tf = cell.textField!
        switch id {
        case "status":
            tf.stringValue = item.task.status.rawValue
            tf.textColor   = item.task.status == .running ? .labelColor : .secondaryLabelColor
        case "cpu":
            let v = item.task.cpuPercent
            tf.stringValue = String(format: "%.1f%%", v)
            tf.textColor   = v > 50 ? .systemRed : (v > 20 ? .systemOrange : (v > 5 ? .labelColor : .secondaryLabelColor))
        case "memory":
            tf.stringValue = ByteCountFormatter.string(fromByteCount: Int64(item.task.memoryBytes), countStyle: .memory)
            tf.textColor   = .labelColor
        case "disk":
            let v = item.task.diskBytesPerSecond
            tf.stringValue = v < 512 ? "—" : formatRate(v)
            tf.textColor   = v > 10_000_000 ? .systemOrange : .secondaryLabelColor
        case "energy":
            tf.stringValue = item.task.energyImpact.rawValue
            tf.textColor   = item.task.energyImpact.color
        case "threads":
            tf.stringValue = "\(item.task.threadCount)"
            tf.textColor   = .secondaryLabelColor
        case "handles":
            tf.stringValue = "\(item.task.handleCount)"
            tf.textColor   = .secondaryLabelColor
        case "pid":
            tf.stringValue = "\(item.id)"
            tf.textColor   = .tertiaryLabelColor
        default: break
        }
        return cell
    }

    func tableViewSelectionDidChange(_ n: Notification) {
        updateEndTaskButtonState()
    }

    private func updateEndTaskButtonState() {
        let killable = getSelectedRows().filter { !$0.task.isProtected && $0.task.id != getpid() }
        endTaskButton.isEnabled = !killable.isEmpty
    }

    private func getSelectedRows() -> [TaskRow] {
        return processTable.selectedRowIndexes.compactMap { idx in
            displayedRows.indices.contains(idx) ? displayedRows[idx] : nil
        }
    }

    func tableView(_ tv: NSTableView, sortDescriptorsDidChange old: [NSSortDescriptor]) {
        guard let d = tv.sortDescriptors.first else { return }
        sortKey = d.key ?? "cpu"; sortAscending = d.ascending; applyFilterAndSort()
    }

    // MARK: - Right-click context menu
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let row = processTable.clickedRow
        guard row >= 0 else { return }

        if !processTable.selectedRowIndexes.contains(row) {
            processTable.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
        }

        let selected = getSelectedRows()
        let killable = selected.filter { !$0.task.isProtected && $0.task.id != getpid() }
        let canKill = !killable.isEmpty

        let endTitle = killable.count > 1 ? "End \(killable.count) Tasks" : "End Task"
        let forceTitle = killable.count > 1 ? "Force Quit \(killable.count) Tasks" : "Force Quit"

        let endItem = NSMenuItem(title: endTitle, action: canKill ? #selector(endSelectedTask) : nil, keyEquivalent: "")
        endItem.target = self; endItem.image = NSImage(systemSymbolName: "stop.fill", accessibilityDescription: nil)
        menu.addItem(endItem)

        let forceItem = NSMenuItem(title: forceTitle, action: canKill ? #selector(forceQuitSelected) : nil, keyEquivalent: "")
        forceItem.target = self; menu.addItem(forceItem)

        menu.addItem(.separator())
        if selected.count == 1, let item = selected.first, !item.task.path.isEmpty {
            let fi = NSMenuItem(title: "Show in Finder", action: #selector(showInFinder), keyEquivalent: "")
            fi.target = self; fi.image = NSImage(systemSymbolName: "folder", accessibilityDescription: nil)
            menu.addItem(fi)
        }
        if selected.count == 1, let item = selected.first {
            let ci = NSMenuItem(title: "Copy PID (\(item.id))", action: #selector(copyPID), keyEquivalent: "")
            ci.target = self; menu.addItem(ci)
        } else if selected.count > 1 {
            let ci = NSMenuItem(title: "Copy PIDs (\(selected.count))", action: #selector(copyPID), keyEquivalent: "")
            ci.target = self; menu.addItem(ci)
        }
    }

    // MARK: - Actions
    @objc private func endSelectedTask() {
        let selected = getSelectedRows()
        let killable = selected.filter { !$0.task.isProtected && $0.task.id != getpid() }
        guard !killable.isEmpty else { return }

        let a = NSAlert()
        if killable.count == 1 {
            let sel = killable[0]
            a.messageText = "End \"\(sel.displayName)\"?"
            a.informativeText = "Quit asks the app to close normally. Force Quit terminates it immediately and may discard unsaved changes."
        } else {
            a.messageText = "End \(killable.count) Selected Processes?"
            let names = killable.prefix(4).map { $0.displayName }.joined(separator: ", ")
            let extra = killable.count > 4 ? " and \(killable.count - 4) more" : ""
            a.informativeText = "Processes: \(names)\(extra)\n\nQuit asks apps to close normally. Force Quit terminates them immediately."
        }
        a.alertStyle = .warning
        a.addButton(withTitle: "Quit")
        a.addButton(withTitle: "Force Quit")
        a.addButton(withTitle: "Cancel")

        switch a.runModal() {
        case .alertFirstButtonReturn:
            killable.forEach { endProcess($0, force: false) }
        case .alertSecondButtonReturn:
            killable.forEach { endProcess($0, force: true) }
        default: break
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.refreshTasks() }
    }

    @objc private func forceQuitSelected() {
        let selected = getSelectedRows()
        let killable = selected.filter { !$0.task.isProtected && $0.task.id != getpid() }
        guard !killable.isEmpty else { return }
        killable.forEach { endProcess($0, force: true) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.refreshTasks() }
    }

    func killSelectedTasksDirectly(force: Bool = false) {
        let selected = getSelectedRows()
        let killable = selected.filter { !$0.task.isProtected && $0.task.id != getpid() }
        guard !killable.isEmpty else { return }
        for item in killable {
            endProcess(item, force: force)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.refreshTasks()
        }
    }

    @objc private func showInFinder() {
        let selected = getSelectedRows()
        guard let item = selected.first, !item.task.path.isEmpty else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.task.path)])
    }

    @objc private func copyPID() {
        let selected = getSelectedRows()
        guard !selected.isEmpty else { return }
        let pidsStr = selected.map { "\($0.id)" }.joined(separator: ", ")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(pidsStr, forType: .string)
    }

    private func endProcess(_ row: TaskRow, force: Bool) {
        guard row.task.id != getpid(), !row.task.isProtected else { return }
        if let app = appMap[row.id] { _ = force ? app.forceTerminate() : app.terminate() }
        else { _ = kill(row.id, force ? SIGKILL : SIGTERM) }
    }

    private func selectedRowIsProtected() -> Bool {
        let killable = getSelectedRows().filter { !$0.task.isProtected && $0.task.id != getpid() }
        return killable.isEmpty
    }

    // MARK: - Adaptive Layout
    func windowDidResize(_ n: Notification) { updateAdaptiveLayout(for: window.frame.size) }

    private func updateAdaptiveLayout(for sz: NSSize) {
        let compact = sz.width < 1060; let narrow = sz.width < 740
        let margin: CGFloat = narrow ? 14 : (compact ? 22 : 32)

        sidebarWidthC?.constant = compact ? (narrow ? 56 : 64) : 236
        sidebarLeadingC?.constant  = compact ? 8 : 10
        sidebarTrailingC?.constant = compact ? -8 : -10
        sidebarStack?.spacing = compact ? 4 : 4
        sidebarTopC?.constant = compact ? 14 : 52

        sectionLabel?.isHidden = compact
        footerLabel?.isHidden = compact
        for item in sidebarItems {
            item.setCompact(compact)
        }

        let isProc = page == .processes
        endTaskButton.title = isProc && !compact ? "End Task" : ""
        endTaskButton.imagePosition = isProc && !compact ? .imageLeading : .imageOnly
        refreshButton.title = isProc && !compact ? "Refresh" : ""
        refreshButton.imagePosition = isProc && !compact ? .imageLeading : .imageOnly

        contentLeadingC.forEach { $0.constant = margin }
        contentTrailingC.forEach { $0.constant = -margin }

        let avail = max(0, content.bounds.width - 2 * margin)
        searchWidthC?.constant = compact ? max(96, min(240, avail - (compact ? 72 : 196) - 36)) : 220

        tableColumns["status"]?.isHidden  = compact
        tableColumns["disk"]?.isHidden    = compact
        tableColumns["energy"]?.isHidden  = compact
        tableColumns["threads"]?.isHidden = narrow || sz.width < 900
        tableColumns["handles"]?.isHidden = narrow || sz.width < 900
        tableColumns["cpu"]?.isHidden     = sz.width < 640
        tableColumns["pid"]?.isHidden     = sz.width < 760

        if let name = tableColumns["name"], let memory = tableColumns["memory"] {
            if narrow { name.width = 110; memory.width = 76 }
            else if compact { name.width = 190; memory.width = 90 }
            else { name.width = 240; memory.width = 100 }
        }
    }

    // MARK: - Format helpers
    private func formatRate(_ bps: Double) -> String {
        guard bps >= 1024 else { return String(format: "%.0f B/s", bps) }
        if bps >= 1_048_576 { return String(format: "%.1f MB/s", bps / 1_048_576) }
        return String(format: "%.0f KB/s", bps / 1024)
    }
}

// MARK: - ProcessNameCell
private final class ProcessNameCell: NSTableCellView {
    private let icon   = NSImageView()
    private let name   = NSTextField(labelWithString: "")
    private let badge  = NSTextField(labelWithString: "●")

    override init(frame: NSRect) { super.init(frame: frame); setup() }
    required init?(coder: NSCoder) { super.init(coder: coder); setup() }

    private func setup() {
        icon.imageScaling = .scaleProportionallyDown
        icon.translatesAutoresizingMaskIntoConstraints = false
        name.font = .systemFont(ofSize: 12.5); name.lineBreakMode = .byTruncatingTail
        name.translatesAutoresizingMaskIntoConstraints = false
        textField = name
        badge.font = .systemFont(ofSize: 8); badge.translatesAutoresizingMaskIntoConstraints = false
        badge.isHidden = true
        addSubview(icon); addSubview(name); addSubview(badge)
        NSLayoutConstraint.activate([
            icon.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4),
            icon.centerYAnchor.constraint(equalTo: centerYAnchor),
            icon.widthAnchor.constraint(equalToConstant: 18), icon.heightAnchor.constraint(equalToConstant: 18),
            name.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 7),
            name.trailingAnchor.constraint(equalTo: badge.leadingAnchor, constant: -4),
            name.centerYAnchor.constraint(equalTo: centerYAnchor),
            badge.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -6),
            badge.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }
    func configure(name nameStr: String, icon img: NSImage?, isProtected: Bool, kind: String) {
        name.stringValue = nameStr
        icon.image = img ?? NSImage(systemSymbolName: "terminal", accessibilityDescription: nameStr)
        badge.isHidden = !isProtected
        badge.textColor = .systemOrange
    }
}

// MARK: - Performance Nav Card
private final class PerfNavCard: NSView {
    let resource: PerfResource
    private let titleLbl  = NSTextField(labelWithString: "")
    private let valueLbl  = NSTextField(labelWithString: "—")
    private let sparkline = MiniSparklineView()
    private let selLayer  = CALayer()
    var isSelected = false { didSet { updateSelection() } }
    private weak var _target: AnyObject?; private var _action: Selector?

    init(resource: PerfResource, target: AnyObject, action: Selector) {
        self.resource = resource; _target = target; _action = action
        super.init(frame: .zero)
        wantsLayer = true; layer?.cornerRadius = 10
        selLayer.cornerRadius = 10
        selLayer.backgroundColor = NSColor.controlAccentColor.withAlphaComponent(0.13).cgColor
        selLayer.frame = bounds; layer?.addSublayer(selLayer)
        selLayer.isHidden = true

        let (name, sym, color): (String, String, NSColor) = {
            switch resource {
            case .cpu:     return ("CPU",     "cpu",             .systemBlue)
            case .memory:  return ("Memory",  "memorychip",      .systemGreen)
            case .disk:    return ("Disk",    "internaldrive",   .systemOrange)
            case .network: return ("Network", "network",         .systemPurple)
            }
        }()

        let icon = NSImageView()
        if let img = NSImage(systemSymbolName: sym, accessibilityDescription: name) {
            icon.image = img.withSymbolConfiguration(.init(pointSize: 12, weight: .medium))
        }
        icon.contentTintColor = color; icon.translatesAutoresizingMaskIntoConstraints = false
        sparkline.lineColor = color; sparkline.translatesAutoresizingMaskIntoConstraints = false

        titleLbl.stringValue = name; titleLbl.font = .systemFont(ofSize: 12, weight: .semibold)
        titleLbl.lineBreakMode = .byTruncatingTail
        titleLbl.translatesAutoresizingMaskIntoConstraints = false
        valueLbl.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        valueLbl.textColor = .secondaryLabelColor
        valueLbl.lineBreakMode = .byTruncatingTail
        valueLbl.translatesAutoresizingMaskIntoConstraints = false

        addSubview(icon); addSubview(titleLbl); addSubview(valueLbl); addSubview(sparkline)
        NSLayoutConstraint.activate([
            icon.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 10),
            icon.topAnchor.constraint(equalTo: topAnchor, constant: 10),
            icon.widthAnchor.constraint(equalToConstant: 14), icon.heightAnchor.constraint(equalToConstant: 14),
            titleLbl.leadingAnchor.constraint(equalTo: icon.trailingAnchor, constant: 6),
            titleLbl.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -8),
            titleLbl.centerYAnchor.constraint(equalTo: icon.centerYAnchor),
            valueLbl.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 10),
            valueLbl.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -8),
            valueLbl.topAnchor.constraint(equalTo: icon.bottomAnchor, constant: 4),
            sparkline.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            sparkline.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
            sparkline.topAnchor.constraint(equalTo: valueLbl.bottomAnchor, constant: 6),
            sparkline.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -8),
            sparkline.heightAnchor.constraint(equalToConstant: 36),
            heightAnchor.constraint(equalToConstant: 94),
        ])

        let click = NSClickGestureRecognizer(target: self, action: #selector(tapped))
        addGestureRecognizer(click)
    }
    required init?(coder: NSCoder) { fatalError() }

    override func layout() { super.layout(); selLayer.frame = bounds }

    @objc private func tapped() { _ = _target?.perform(_action, with: self) }

    func setValue(_ v: String, history: [Double], max: Double?) {
        valueLbl.stringValue = v
        sparkline.values = history
        if let m = max { sparkline.maximum = m }
        else { sparkline.maximum = (history.max() ?? 1) * 1.2 }
    }

    private func updateSelection() {
        selLayer.isHidden = !isSelected
        layer?.borderWidth = isSelected ? 1.5 : 0
        layer?.borderColor = isSelected ? NSColor.controlAccentColor.withAlphaComponent(0.5).cgColor : nil
    }
}

// MARK: - Core Tile View (Individual CPU Core)
private final class CoreTileView: NSView {
    let coreIndex: Int
    let isPCore: Bool
    private let titleLabel = NSTextField(labelWithString: "")
    private let valueLabel = NSTextField(labelWithString: "0%")
    private let sparkline = MiniSparklineView()

    init(coreIndex: Int, isPCore: Bool) {
        self.coreIndex = coreIndex
        self.isPCore = isPCore
        super.init(frame: .zero)
        wantsLayer = true
        layer?.cornerRadius = 8
        layer?.borderWidth = 1
        layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.2).cgColor
        layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.4).cgColor

        let accent: NSColor = isPCore ? .systemBlue : .systemTeal
        sparkline.lineColor = accent
        sparkline.maximum = 100
        sparkline.translatesAutoresizingMaskIntoConstraints = false

        let kind = isPCore ? "P" : "E"
        titleLabel.stringValue = "Core \(coreIndex + 1) (\(kind))"
        titleLabel.font = .systemFont(ofSize: 10.5, weight: .semibold)
        titleLabel.textColor = isPCore ? .systemBlue : .systemTeal
        titleLabel.lineBreakMode = .byTruncatingTail
        titleLabel.translatesAutoresizingMaskIntoConstraints = false

        valueLabel.font = .monospacedDigitSystemFont(ofSize: 12, weight: .medium)
        valueLabel.textColor = .labelColor
        valueLabel.setContentHuggingPriority(.required, for: .horizontal)
        valueLabel.setContentCompressionResistancePriority(.required, for: .horizontal)
        valueLabel.translatesAutoresizingMaskIntoConstraints = false

        addSubview(titleLabel)
        addSubview(valueLabel)
        addSubview(sparkline)

        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: topAnchor, constant: 6),
            titleLabel.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: valueLabel.leadingAnchor, constant: -4),

            valueLabel.topAnchor.constraint(equalTo: topAnchor, constant: 5),
            valueLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),

            sparkline.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            sparkline.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 6),
            sparkline.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -6),
            sparkline.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -6),
        ])
    }
    required init?(coder: NSCoder) { fatalError() }

    func update(percent: Double, history: [Double]) {
        valueLabel.stringValue = String(format: "%.0f%%", percent)
        valueLabel.textColor = percent > 80 ? .systemRed : (percent > 50 ? .systemOrange : .labelColor)
        sparkline.values = history
    }
}

// MARK: - Logical Cores Grid View
private final class LogicalCoresGridView: NSView {
    private var tiles: [CoreTileView] = []
    private var gridConstraints: [NSLayoutConstraint] = []

    override init(frame: NSRect) { super.init(frame: frame) }
    required init?(coder: NSCoder) { fatalError() }

    func update(perCore: [Double], perCoreHistory: [[Double]]) {
        if tiles.count != perCore.count {
            rebuild(count: perCore.count)
        }
        for (i, tile) in tiles.enumerated() where i < perCore.count {
            let hist = i < perCoreHistory.count ? perCoreHistory[i] : [perCore[i]]
            tile.update(percent: perCore[i], history: hist)
        }
    }

    private func rebuild(count: Int) {
        subviews.forEach { $0.removeFromSuperview() }
        NSLayoutConstraint.deactivate(gridConstraints)
        tiles = []
        gridConstraints = []

        let pCount = ProcessReader.pCoreCount()
        for i in 0..<count {
            let isPCore = i < pCount
            let tile = CoreTileView(coreIndex: i, isPCore: isPCore)
            tile.translatesAutoresizingMaskIntoConstraints = false
            addSubview(tile)
            tiles.append(tile)
        }

        let cols = count > 8 ? 4 : (count > 4 ? 4 : 2)
        let rows = Int(ceil(Double(count) / Double(cols)))

        var rowViews: [[CoreTileView]] = []
        for r in 0..<rows {
            var currRow: [CoreTileView] = []
            for c in 0..<cols {
                let idx = r * cols + c
                if idx < tiles.count { currRow.append(tiles[idx]) }
            }
            rowViews.append(currRow)
        }

        for (rIdx, row) in rowViews.enumerated() {
            for (cIdx, tile) in row.enumerated() {
                if cIdx == 0 {
                    gridConstraints.append(tile.leadingAnchor.constraint(equalTo: leadingAnchor))
                } else {
                    let prev = row[cIdx - 1]
                    gridConstraints.append(tile.leadingAnchor.constraint(equalTo: prev.trailingAnchor, constant: 8))
                    gridConstraints.append(tile.widthAnchor.constraint(equalTo: prev.widthAnchor))
                }
                if cIdx == row.count - 1 {
                    gridConstraints.append(tile.trailingAnchor.constraint(equalTo: trailingAnchor))
                }
                if rIdx == 0 {
                    gridConstraints.append(tile.topAnchor.constraint(equalTo: topAnchor))
                } else {
                    let above = rowViews[rIdx - 1][cIdx]
                    gridConstraints.append(tile.topAnchor.constraint(equalTo: above.bottomAnchor, constant: 8))
                    gridConstraints.append(tile.heightAnchor.constraint(equalTo: above.heightAnchor))
                }
                if rIdx == rowViews.count - 1 {
                    gridConstraints.append(tile.bottomAnchor.constraint(equalTo: bottomAnchor))
                }
            }
        }
        NSLayoutConstraint.activate(gridConstraints)
    }
}

// MARK: - CPU Detail View
private final class CPUDetailView: NSView {
    private let scrollView = NSScrollView()
    private let docView    = NSView()
    private let header     = DetailHeader(title: "CPU", subtitle: "")
    private let graph      = SparklineView(color: .systemBlue, fill: NSColor.systemBlue.withAlphaComponent(0.12), max: 100)
    private let grid       = StatGrid(cols: 3)
    private let sectionLbl = NSTextField(labelWithString: "LOGICAL PROCESSORS — ALL-CORE BREAKDOWN")
    private let allCoresGrid = LogicalCoresGridView()

    override init(frame: NSRect) { super.init(frame: frame); setup() }
    required init?(coder: NSCoder) { fatalError() }

    private func setup() {
        let chip = ProcessReader.chipName()
        header.subtitle = chip

        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .noBorder
        addSubview(scrollView)

        docView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.documentView = docView

        sectionLbl.font = .systemFont(ofSize: 10, weight: .bold)
        sectionLbl.textColor = .tertiaryLabelColor
        sectionLbl.lineBreakMode = .byTruncatingTail
        sectionLbl.translatesAutoresizingMaskIntoConstraints = false

        header.translatesAutoresizingMaskIntoConstraints = false
        graph.translatesAutoresizingMaskIntoConstraints = false
        grid.translatesAutoresizingMaskIntoConstraints = false
        allCoresGrid.translatesAutoresizingMaskIntoConstraints = false

        docView.addSubview(header)
        docView.addSubview(graph)
        docView.addSubview(grid)
        docView.addSubview(sectionLbl)
        docView.addSubview(allCoresGrid)

        grid.setStats([
            ("Utilization", "—"), ("Processes", "—"), ("Cores", "—"),
            ("Speed", "N/A"),     ("Threads",   "—"), ("Uptime", "—"),
        ])

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: bottomAnchor),

            docView.leadingAnchor.constraint(equalTo: scrollView.contentView.leadingAnchor),
            docView.trailingAnchor.constraint(equalTo: scrollView.contentView.trailingAnchor),
            docView.topAnchor.constraint(equalTo: scrollView.contentView.topAnchor),

            header.topAnchor.constraint(equalTo: docView.topAnchor, constant: 16),
            header.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            header.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),

            graph.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 14),
            graph.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            graph.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),
            graph.heightAnchor.constraint(equalToConstant: 140),

            grid.topAnchor.constraint(equalTo: graph.bottomAnchor, constant: 14),
            grid.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            grid.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),

            sectionLbl.topAnchor.constraint(equalTo: grid.bottomAnchor, constant: 20),
            sectionLbl.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            sectionLbl.trailingAnchor.constraint(lessThanOrEqualTo: docView.trailingAnchor, constant: -16),

            allCoresGrid.topAnchor.constraint(equalTo: sectionLbl.bottomAnchor, constant: 10),
            allCoresGrid.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            allCoresGrid.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),
            allCoresGrid.heightAnchor.constraint(equalToConstant: 168),
            allCoresGrid.bottomAnchor.constraint(equalTo: docView.bottomAnchor, constant: -20)
        ])
    }

    func update(cpuPct: Double, history: [Double], perCore: [Double], perCoreHistory: [[Double]], processes: Int, threads: Int, uptime: String) {
        graph.values = history
        let pc = ProcessReader.pCoreCount(); let ec = ProcessReader.eCoreCount()
        let coreStr = pc > 0 && ec > 0 ? "\(pc + ec) (\(pc)P + \(ec)E)" : "\(ProcessInfo.processInfo.activeProcessorCount)"
        sectionLbl.stringValue = "LOGICAL PROCESSORS — ALL-CORE BREAKDOWN (\(pc) Performance · \(ec) Efficiency)"
        grid.setStats([
            ("Utilization", String(format: "%.1f%%", cpuPct)),
            ("Processes",   "\(processes)"),
            ("Cores",        coreStr),
            ("Architecture", "ARM64 Apple Silicon"),
            ("Threads",      "\(threads)"),
            ("Uptime",       uptime),
        ])
        allCoresGrid.update(perCore: perCore, perCoreHistory: perCoreHistory)
    }
}

// MARK: - Memory Detail View
private final class MemDetailView: NSView {
    private let header  = DetailHeader(title: "Memory", subtitle: "")
    private let bar     = MemoryBarView()
    private let legend  = MemoryLegendView()
    private let graph   = SparklineView(color: .systemGreen, fill: NSColor.systemGreen.withAlphaComponent(0.12), max: 100)
    private let grid    = StatGrid(cols: 3)

    override init(frame: NSRect) { super.init(frame: frame); setup() }
    required init?(coder: NSCoder) { fatalError() }

    private func setup() {
        let totalGB = Double(ProcessInfo.processInfo.physicalMemory) / 1_073_741_824
        header.subtitle = String(format: "%.0f GB", totalGB)
        let views: [NSView] = [header, bar, legend, graph, grid]
        for v in views {
            v.translatesAutoresizingMaskIntoConstraints = false
            addSubview(v)
        }
        grid.setStats([
            ("In Use", "—"),      ("Available", "—"),  ("Wired Memory", "—"),
            ("App Memory", "—"),  ("Compressed", "—"), ("Cached Files", "—"),
        ])
        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: topAnchor, constant: 20),
            header.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            header.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
            bar.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 16),
            bar.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            bar.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
            bar.heightAnchor.constraint(equalToConstant: 20),
            legend.topAnchor.constraint(equalTo: bar.bottomAnchor, constant: 8),
            legend.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            legend.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
            legend.heightAnchor.constraint(equalToConstant: 18),
            graph.topAnchor.constraint(equalTo: legend.bottomAnchor, constant: 12),
            graph.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            graph.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
            graph.heightAnchor.constraint(equalTo: heightAnchor, multiplier: 0.32),
            grid.topAnchor.constraint(equalTo: graph.bottomAnchor, constant: 14),
            grid.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            grid.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
        ])
    }

    func update(usedBytes: UInt64, totalBytes: UInt64, wiredBytes: UInt64,
                compressedBytes: UInt64, appBytes: UInt64, cachedBytes: UInt64,
                freeBytes: UInt64, history: [Double]) {
        graph.values = history
        let total = Double(totalBytes)
        bar.segments = [
            (NSColor.systemGreen,  Double(appBytes) / total),
            (NSColor.systemOrange, Double(wiredBytes) / total),
            (NSColor.systemPurple, Double(compressedBytes) / total),
            (NSColor.systemBlue.withAlphaComponent(0.5), Double(cachedBytes) / total),
        ]
        legend.segments = [
            (.systemGreen,  "App Memory"),
            (.systemOrange, "Wired"),
            (.systemPurple, "Compressed"),
            (.systemBlue.withAlphaComponent(0.6), "Cached"),
        ]
        func fmt(_ b: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(b), countStyle: .memory) }
        let avail = totalBytes > usedBytes ? totalBytes - usedBytes : 0
        grid.setStats([
            ("In Use",       fmt(usedBytes)),   ("Available",  fmt(avail)),        ("Wired Memory", fmt(wiredBytes)),
            ("App Memory",   fmt(appBytes)),    ("Compressed", fmt(compressedBytes)), ("Cached Files", fmt(cachedBytes)),
        ])
    }
}

// MARK: - Disk Detail View (Performance tab)
private final class DiskDetailView: NSView {
    private let header = DetailHeader(title: "Disk Activity", subtitle: "Real-Time Throughput")
    private let graph  = DualSparklineView(color1: .systemBlue, color2: .systemOrange, label1: "Read", label2: "Write")
    private let grid   = StatGrid(cols: 2)

    override init(frame: NSRect) { super.init(frame: frame); setup() }
    required init?(coder: NSCoder) { fatalError() }

    private func setup() {
        let views: [NSView] = [header, graph, grid]
        for v in views {
            v.translatesAutoresizingMaskIntoConstraints = false
            addSubview(v)
        }
        grid.setStats([("Read Speed", "—"), ("Write Speed", "—")])
        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: topAnchor, constant: 20),
            header.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            header.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
            graph.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 16),
            graph.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            graph.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
            graph.heightAnchor.constraint(equalTo: heightAnchor, multiplier: 0.55),
            grid.topAnchor.constraint(equalTo: graph.bottomAnchor, constant: 16),
            grid.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            grid.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
        ])
    }

    func update(readBPS: Double, writeBPS: Double, readHistory: [Double], writeHistory: [Double]) {
        graph.set(values1: readHistory, values2: writeHistory)
        grid.setStats([("Read Speed", fmt(readBPS)), ("Write Speed", fmt(writeBPS))])
    }
    private func fmt(_ bps: Double) -> String {
        guard bps >= 1024 else { return "—" }
        if bps >= 1_048_576 { return String(format: "%.1f MB/s", bps / 1_048_576) }
        return String(format: "%.0f KB/s", bps / 1024)
    }
}

// MARK: - Network Detail View
private final class NetDetailView: NSView {
    private let header = DetailHeader(title: "Network", subtitle: "Ethernet / Wi-Fi")
    private let graph  = DualSparklineView(color1: .systemBlue, color2: .systemGreen, label1: "Send", label2: "Receive")
    private let grid   = StatGrid(cols: 2)

    override init(frame: NSRect) { super.init(frame: frame); setup() }
    required init?(coder: NSCoder) { fatalError() }

    private func setup() {
        let views: [NSView] = [header, graph, grid]
        for v in views {
            v.translatesAutoresizingMaskIntoConstraints = false
            addSubview(v)
        }
        grid.setStats([("Send", "—"), ("Receive", "—")])
        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: topAnchor, constant: 20),
            header.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            header.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
            graph.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 16),
            graph.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            graph.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
            graph.heightAnchor.constraint(equalTo: heightAnchor, multiplier: 0.55),
            grid.topAnchor.constraint(equalTo: graph.bottomAnchor, constant: 16),
            grid.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 20),
            grid.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -20),
        ])
        if let name = primaryInterface() { header.subtitle = name }
    }
    func update(sentBPS: Double, recvBPS: Double, sentHistory: [Double], recvHistory: [Double]) {
        graph.set(values1: sentHistory, values2: recvHistory)
        grid.setStats([("Send", fmt(sentBPS)), ("Receive", fmt(recvBPS))])
    }
    private func fmt(_ bps: Double) -> String {
        guard bps >= 100 else { return "—" }
        if bps >= 1_048_576 { return String(format: "%.1f MB/s", bps / 1_048_576) }
        if bps >= 1024 { return String(format: "%.0f KB/s", bps / 1024) }
        return String(format: "%.0f B/s", bps)
    }
    private func primaryInterface() -> String? {
        var addrs: UnsafeMutablePointer<ifaddrs>? = nil
        guard getifaddrs(&addrs) == 0, let start = addrs else { return nil }
        defer { freeifaddrs(start) }
        var ptr: UnsafeMutablePointer<ifaddrs>? = start
        while let cur = ptr {
            let ifa = cur.pointee
            if ifa.ifa_flags & UInt32(IFF_LOOPBACK) == 0,
               let sa = ifa.ifa_addr, sa.pointee.sa_family == UInt8(AF_LINK),
               let n = ifa.ifa_name {
                return String(cString: n)
            }
            ptr = ifa.ifa_next
        }
        return nil
    }
}

// MARK: - Battery Gauge Visualizer
private final class BatteryGaugeView: NSView {
    var percent: Int = 100 { didSet { needsDisplay = true } }
    var isCharging: Bool = false { didSet { needsDisplay = true } }

    override init(frame: NSRect) { super.init(frame: frame); wantsLayer = true }
    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        let b = bounds.insetBy(dx: 2, dy: 4)
        guard b.width > 20, b.height > 10 else { return }

        // Battery outer shell
        let shellWidth = b.width - 6
        let shellRect = NSRect(x: b.minX, y: b.minY, width: shellWidth, height: b.height)
        let shellPath = NSBezierPath(roundedRect: shellRect, xRadius: 6, yRadius: 6)
        shellPath.lineWidth = 2.5
        NSColor.secondaryLabelColor.withAlphaComponent(0.6).setStroke()
        shellPath.stroke()

        // Battery terminal tip
        let tipRect = NSRect(x: b.minX + shellWidth + 1.5, y: b.minY + (b.height - 12) / 2, width: 3.5, height: 12)
        let tipPath = NSBezierPath(roundedRect: tipRect, xRadius: 1.5, yRadius: 1.5)
        NSColor.secondaryLabelColor.withAlphaComponent(0.6).setFill()
        tipPath.fill()

        // Battery interior fill
        let fillInset: CGFloat = 3.5
        let maxFillWidth = shellWidth - (fillInset * 2)
        let curFraction = CGFloat(min(100, max(0, percent))) / 100.0
        let fillWidth = max(2, maxFillWidth * curFraction)
        let fillRect = NSRect(x: b.minX + fillInset, y: b.minY + fillInset, width: fillWidth, height: b.height - (fillInset * 2))
        let fillPath = NSBezierPath(roundedRect: fillRect, xRadius: 3.5, yRadius: 3.5)

        let fillColor: NSColor
        if percent > 20 {
            fillColor = isCharging ? .systemGreen : .systemGreen
        } else if percent > 10 {
            fillColor = .systemOrange
        } else {
            fillColor = .systemRed
        }
        fillColor.setFill()
        fillPath.fill()

        // Charging lightning symbol overlay
        if isCharging, let bolt = NSImage(systemSymbolName: "bolt.fill", accessibilityDescription: nil) {
            let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .bold)
            let img = bolt.withSymbolConfiguration(config)
            let boltRect = NSRect(x: b.minX + (shellWidth - 14) / 2, y: b.minY + (b.height - 16) / 2, width: 14, height: 16)
            img?.draw(in: boltRect)
        }
    }
}

// MARK: - Battery Page View (In-Depth Diagnostics)
private final class BatteryPageView: NSView {
    private let scrollView = NSScrollView()
    private let docView = NSView()

    // Overview Card
    private let overviewCard = NSView()
    private let gaugeView = BatteryGaugeView()
    private let percentLabel = NSTextField(labelWithString: "—%")
    private let statusHeadline = NSTextField(labelWithString: "Checking power...")
    private let timeRemainingLabel = NSTextField(labelWithString: "")
    private let powerBadge = NSTextField(labelWithString: "— W")
    private let sourceLabel = NSTextField(labelWithString: "Power Source: —")

    // Health Card
    private let healthCard = NSView()
    private let healthGrid = StatGrid(cols: 3)
    private let healthProgress = NSProgressIndicator()

    // Electrical Card
    private let electricalCard = NSView()
    private let electricalGrid = StatGrid(cols: 3)

    override init(frame: NSRect) { super.init(frame: frame); setup() }
    required init?(coder: NSCoder) { fatalError() }

    private func setup() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .noBorder
        addSubview(scrollView)

        docView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.documentView = docView

        [overviewCard, healthCard, electricalCard].forEach {
            $0.wantsLayer = true
            $0.layer?.cornerRadius = 14
            $0.layer?.borderWidth = 1
            $0.layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.25).cgColor
            $0.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.4).cgColor
            $0.translatesAutoresizingMaskIntoConstraints = false
            docView.addSubview($0)
        }

        setupOverviewCard()
        setupHealthCard()
        setupElectricalCard()

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: bottomAnchor),

            docView.leadingAnchor.constraint(equalTo: scrollView.contentView.leadingAnchor),
            docView.trailingAnchor.constraint(equalTo: scrollView.contentView.trailingAnchor),
            docView.topAnchor.constraint(equalTo: scrollView.contentView.topAnchor),

            overviewCard.topAnchor.constraint(equalTo: docView.topAnchor, constant: 16),
            overviewCard.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            overviewCard.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),
            overviewCard.heightAnchor.constraint(equalToConstant: 120),

            healthCard.topAnchor.constraint(equalTo: overviewCard.bottomAnchor, constant: 16),
            healthCard.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            healthCard.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),

            electricalCard.topAnchor.constraint(equalTo: healthCard.bottomAnchor, constant: 16),
            electricalCard.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            electricalCard.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),
            electricalCard.bottomAnchor.constraint(equalTo: docView.bottomAnchor, constant: -20),
        ])
    }

    private func setupOverviewCard() {
        gaugeView.translatesAutoresizingMaskIntoConstraints = false

        percentLabel.font = .systemFont(ofSize: 32, weight: .light)
        percentLabel.setContentHuggingPriority(.required, for: .horizontal)
        percentLabel.setContentCompressionResistancePriority(.required, for: .horizontal)
        percentLabel.translatesAutoresizingMaskIntoConstraints = false

        statusHeadline.font = .systemFont(ofSize: 14, weight: .semibold)
        statusHeadline.lineBreakMode = .byTruncatingTail
        statusHeadline.translatesAutoresizingMaskIntoConstraints = false

        timeRemainingLabel.font = .systemFont(ofSize: 12)
        timeRemainingLabel.textColor = .secondaryLabelColor
        timeRemainingLabel.lineBreakMode = .byTruncatingTail
        timeRemainingLabel.translatesAutoresizingMaskIntoConstraints = false

        powerBadge.font = .monospacedDigitSystemFont(ofSize: 14, weight: .bold)
        powerBadge.textColor = .controlAccentColor
        powerBadge.alignment = .right
        powerBadge.setContentHuggingPriority(.required, for: .horizontal)
        powerBadge.setContentCompressionResistancePriority(.required, for: .horizontal)
        powerBadge.translatesAutoresizingMaskIntoConstraints = false

        sourceLabel.font = .systemFont(ofSize: 11)
        sourceLabel.textColor = .tertiaryLabelColor
        sourceLabel.alignment = .right
        sourceLabel.setContentHuggingPriority(.required, for: .horizontal)
        sourceLabel.setContentCompressionResistancePriority(.required, for: .horizontal)
        sourceLabel.translatesAutoresizingMaskIntoConstraints = false

        overviewCard.addSubview(gaugeView)
        overviewCard.addSubview(percentLabel)
        overviewCard.addSubview(statusHeadline)
        overviewCard.addSubview(timeRemainingLabel)
        overviewCard.addSubview(powerBadge)
        overviewCard.addSubview(sourceLabel)

        NSLayoutConstraint.activate([
            gaugeView.leadingAnchor.constraint(equalTo: overviewCard.leadingAnchor, constant: 18),
            gaugeView.centerYAnchor.constraint(equalTo: overviewCard.centerYAnchor),
            gaugeView.widthAnchor.constraint(equalToConstant: 64),
            gaugeView.heightAnchor.constraint(equalToConstant: 34),

            percentLabel.leadingAnchor.constraint(equalTo: gaugeView.trailingAnchor, constant: 12),
            percentLabel.centerYAnchor.constraint(equalTo: overviewCard.centerYAnchor),

            statusHeadline.leadingAnchor.constraint(equalTo: percentLabel.trailingAnchor, constant: 16),
            statusHeadline.topAnchor.constraint(equalTo: overviewCard.topAnchor, constant: 36),
            statusHeadline.trailingAnchor.constraint(lessThanOrEqualTo: powerBadge.leadingAnchor, constant: -12),

            timeRemainingLabel.leadingAnchor.constraint(equalTo: statusHeadline.leadingAnchor),
            timeRemainingLabel.topAnchor.constraint(equalTo: statusHeadline.bottomAnchor, constant: 4),
            timeRemainingLabel.trailingAnchor.constraint(lessThanOrEqualTo: sourceLabel.leadingAnchor, constant: -12),

            powerBadge.trailingAnchor.constraint(equalTo: overviewCard.trailingAnchor, constant: -20),
            powerBadge.topAnchor.constraint(equalTo: overviewCard.topAnchor, constant: 36),

            sourceLabel.trailingAnchor.constraint(equalTo: overviewCard.trailingAnchor, constant: -20),
            sourceLabel.topAnchor.constraint(equalTo: powerBadge.bottomAnchor, constant: 4),
        ])
    }

    private func setupHealthCard() {
        let title = NSTextField(labelWithString: "BATTERY HEALTH & LONGEVITY")
        title.font = .systemFont(ofSize: 10, weight: .bold)
        title.textColor = .tertiaryLabelColor
        title.translatesAutoresizingMaskIntoConstraints = false

        healthGrid.translatesAutoresizingMaskIntoConstraints = false

        healthCard.addSubview(title)
        healthCard.addSubview(healthGrid)

        healthGrid.setStats([
            ("Maximum Capacity", "—"), ("Cycle Count", "—"),      ("Condition", "—"),
            ("Full Capacity", "—"),    ("Design Capacity", "—"),  ("Health Degradation", "—")
        ])

        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: healthCard.topAnchor, constant: 14),
            title.leadingAnchor.constraint(equalTo: healthCard.leadingAnchor, constant: 16),

            healthGrid.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 12),
            healthGrid.leadingAnchor.constraint(equalTo: healthCard.leadingAnchor, constant: 16),
            healthGrid.trailingAnchor.constraint(equalTo: healthCard.trailingAnchor, constant: -16),
            healthGrid.bottomAnchor.constraint(equalTo: healthCard.bottomAnchor, constant: -16),
        ])
    }

    private func setupElectricalCard() {
        let title = NSTextField(labelWithString: "ELECTRICAL & HARDWARE DIAGNOSTICS")
        title.font = .systemFont(ofSize: 10, weight: .bold)
        title.textColor = .tertiaryLabelColor
        title.translatesAutoresizingMaskIntoConstraints = false

        electricalGrid.translatesAutoresizingMaskIntoConstraints = false

        electricalCard.addSubview(title)
        electricalCard.addSubview(electricalGrid)

        electricalGrid.setStats([
            ("Voltage", "—"),          ("Amperage (Current)", "—"), ("Power Draw", "—"),
            ("Controller / IC", "—"),  ("Serial Number", "—"),      ("Charging Allowed", "—")
        ])

        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: electricalCard.topAnchor, constant: 14),
            title.leadingAnchor.constraint(equalTo: electricalCard.leadingAnchor, constant: 16),

            electricalGrid.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 12),
            electricalGrid.leadingAnchor.constraint(equalTo: electricalCard.leadingAnchor, constant: 16),
            electricalGrid.trailingAnchor.constraint(equalTo: electricalCard.trailingAnchor, constant: -16),
            electricalGrid.bottomAnchor.constraint(equalTo: electricalCard.bottomAnchor, constant: -16),
        ])
    }

    func update(battery: BatteryData) {
        gaugeView.percent = battery.currentCapacityPercent
        gaugeView.isCharging = battery.isCharging || battery.isPluggedIn

        percentLabel.stringValue = "\(battery.currentCapacityPercent)%"

        if battery.fullyCharged {
            statusHeadline.stringValue = "Fully Charged"
            timeRemainingLabel.stringValue = "Connected to power"
        } else if battery.isCharging {
            statusHeadline.stringValue = "Charging on Power Adapter"
            if battery.timeRemainingMinutes > 0 && battery.timeRemainingMinutes < 1000 {
                let h = battery.timeRemainingMinutes / 60
                let m = battery.timeRemainingMinutes % 60
                timeRemainingLabel.stringValue = h > 0 ? "\(h) hr \(m) min until full" : "\(m) min until full"
            } else {
                timeRemainingLabel.stringValue = "Calculating time to full..."
            }
        } else if battery.isPluggedIn {
            statusHeadline.stringValue = "Plugged in, Not Charging"
            timeRemainingLabel.stringValue = "Power supplied by adapter"
        } else {
            statusHeadline.stringValue = "On Battery (Discharging)"
            if battery.timeRemainingMinutes > 0 && battery.timeRemainingMinutes < 1440 {
                let h = battery.timeRemainingMinutes / 60
                let m = battery.timeRemainingMinutes % 60
                timeRemainingLabel.stringValue = h > 0 ? "\(h) hrs \(m) mins remaining" : "\(m) mins remaining"
            } else {
                timeRemainingLabel.stringValue = "Calculating battery life..."
            }
        }

        powerBadge.stringValue = String(format: "%.1f W", battery.wattage)
        powerBadge.textColor = battery.isCharging ? .systemGreen : (battery.isPluggedIn ? .systemBlue : .labelColor)
        sourceLabel.stringValue = battery.isPluggedIn ? "Power: AC Adapter" : "Power: Internal Battery"

        let degradation = max(0, 100.0 - battery.healthPercent)
        healthGrid.setStats([
            ("Maximum Capacity", String(format: "%.1f%%", battery.healthPercent)),
            ("Cycle Count", "\(battery.cycleCount) of 1,000"),
            ("Condition", battery.condition),
            ("Full Capacity", "\(battery.fullChargeCapacityMAh) mAh"),
            ("Design Capacity", "\(battery.designCapacityMAh) mAh"),
            ("Health Degradation", String(format: "-%.1f%%", degradation)),
        ])

        let voltStr = String(format: "%.2f V (%d mV)", Double(battery.voltageMilliVolts) / 1000.0, battery.voltageMilliVolts)
        let ampStr = String(format: "%d mA", battery.amperageMilliAmps)
        electricalGrid.setStats([
            ("Voltage", voltStr),
            ("Amperage (Current)", ampStr),
            ("Power Draw", String(format: "%.2f Watts", battery.wattage)),
            ("Controller / IC", battery.deviceName),
            ("Serial Number", battery.serialNumber),
            ("Charging Allowed", battery.isPluggedIn ? "Yes" : "On Battery"),
        ])
    }
}

// MARK: - Disk & S.M.A.R.T. Page View
private final class DiskSMARTPageView: NSView {
    private let scrollView = NSScrollView()
    private let docView = NSView()

    // Drive Header Card
    private let headerCard = NSView()
    private let driveIcon = NSImageView()
    private let driveModelLabel = NSTextField(labelWithString: "Apple Internal SSD")
    private let protocolLabel = NSTextField(labelWithString: "Apple Fabric · NVMe Solid State Drive")
    private let smartBadge = NSTextField(labelWithString: "  S.M.A.R.T. Verified  ")

    // Storage Allocation Card
    private let storageCard = NSView()
    private let storageBar = MemoryBarView()
    private let storageText = NSTextField(labelWithString: "Calculating space...")

    // SMART Attributes Card
    private let smartCard = NSView()
    private let smartGrid = StatGrid(cols: 3)

    override init(frame: NSRect) { super.init(frame: frame); setup() }
    required init?(coder: NSCoder) { fatalError() }

    private func setup() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .noBorder
        addSubview(scrollView)

        docView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.documentView = docView

        [headerCard, storageCard, smartCard].forEach {
            $0.wantsLayer = true
            $0.layer?.cornerRadius = 14
            $0.layer?.borderWidth = 1
            $0.layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.25).cgColor
            $0.layer?.backgroundColor = NSColor.controlBackgroundColor.withAlphaComponent(0.4).cgColor
            $0.translatesAutoresizingMaskIntoConstraints = false
            docView.addSubview($0)
        }

        setupHeaderCard()
        setupStorageCard()
        setupSMARTCard()

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: bottomAnchor),

            docView.leadingAnchor.constraint(equalTo: scrollView.contentView.leadingAnchor),
            docView.trailingAnchor.constraint(equalTo: scrollView.contentView.trailingAnchor),
            docView.topAnchor.constraint(equalTo: scrollView.contentView.topAnchor),

            headerCard.topAnchor.constraint(equalTo: docView.topAnchor, constant: 16),
            headerCard.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            headerCard.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),
            headerCard.heightAnchor.constraint(equalToConstant: 96),

            storageCard.topAnchor.constraint(equalTo: headerCard.bottomAnchor, constant: 16),
            storageCard.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            storageCard.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),

            smartCard.topAnchor.constraint(equalTo: storageCard.bottomAnchor, constant: 16),
            smartCard.leadingAnchor.constraint(equalTo: docView.leadingAnchor, constant: 16),
            smartCard.trailingAnchor.constraint(equalTo: docView.trailingAnchor, constant: -16),
            smartCard.bottomAnchor.constraint(equalTo: docView.bottomAnchor, constant: -20),
        ])
    }

    private func setupHeaderCard() {
        if let sym = NSImage(systemSymbolName: "internaldrive", accessibilityDescription: nil) {
            driveIcon.image = sym.withSymbolConfiguration(.init(pointSize: 28, weight: .regular))
        }
        driveIcon.contentTintColor = .controlAccentColor
        driveIcon.translatesAutoresizingMaskIntoConstraints = false

        driveModelLabel.font = .systemFont(ofSize: 18, weight: .semibold)
        driveModelLabel.lineBreakMode = .byTruncatingTail
        driveModelLabel.translatesAutoresizingMaskIntoConstraints = false

        protocolLabel.font = .systemFont(ofSize: 12)
        protocolLabel.textColor = .secondaryLabelColor
        protocolLabel.lineBreakMode = .byTruncatingTail
        protocolLabel.translatesAutoresizingMaskIntoConstraints = false

        smartBadge.font = .systemFont(ofSize: 11, weight: .semibold)
        smartBadge.textColor = .systemGreen
        smartBadge.wantsLayer = true
        smartBadge.layer?.cornerRadius = 6
        smartBadge.layer?.backgroundColor = NSColor.systemGreen.withAlphaComponent(0.12).cgColor
        smartBadge.setContentHuggingPriority(.required, for: .horizontal)
        smartBadge.setContentCompressionResistancePriority(.required, for: .horizontal)
        smartBadge.translatesAutoresizingMaskIntoConstraints = false

        headerCard.addSubview(driveIcon)
        headerCard.addSubview(driveModelLabel)
        headerCard.addSubview(protocolLabel)
        headerCard.addSubview(smartBadge)

        NSLayoutConstraint.activate([
            driveIcon.leadingAnchor.constraint(equalTo: headerCard.leadingAnchor, constant: 20),
            driveIcon.centerYAnchor.constraint(equalTo: headerCard.centerYAnchor),
            driveIcon.widthAnchor.constraint(equalToConstant: 36),
            driveIcon.heightAnchor.constraint(equalToConstant: 36),

            driveModelLabel.leadingAnchor.constraint(equalTo: driveIcon.trailingAnchor, constant: 16),
            driveModelLabel.topAnchor.constraint(equalTo: headerCard.topAnchor, constant: 26),
            driveModelLabel.trailingAnchor.constraint(lessThanOrEqualTo: smartBadge.leadingAnchor, constant: -12),

            protocolLabel.leadingAnchor.constraint(equalTo: driveModelLabel.leadingAnchor),
            protocolLabel.topAnchor.constraint(equalTo: driveModelLabel.bottomAnchor, constant: 3),
            protocolLabel.trailingAnchor.constraint(lessThanOrEqualTo: smartBadge.leadingAnchor, constant: -12),

            smartBadge.trailingAnchor.constraint(equalTo: headerCard.trailingAnchor, constant: -20),
            smartBadge.centerYAnchor.constraint(equalTo: headerCard.centerYAnchor),
            smartBadge.heightAnchor.constraint(equalToConstant: 26),
        ])
    }

    private func setupStorageCard() {
        let title = NSTextField(labelWithString: "STORAGE ALLOCATION & USAGE")
        title.font = .systemFont(ofSize: 10, weight: .bold)
        title.textColor = .tertiaryLabelColor
        title.translatesAutoresizingMaskIntoConstraints = false

        storageBar.translatesAutoresizingMaskIntoConstraints = false

        storageText.font = .systemFont(ofSize: 12, weight: .medium)
        storageText.textColor = .secondaryLabelColor
        storageText.lineBreakMode = .byTruncatingTail
        storageText.translatesAutoresizingMaskIntoConstraints = false

        storageCard.addSubview(title)
        storageCard.addSubview(storageBar)
        storageCard.addSubview(storageText)

        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: storageCard.topAnchor, constant: 14),
            title.leadingAnchor.constraint(equalTo: storageCard.leadingAnchor, constant: 16),

            storageBar.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 12),
            storageBar.leadingAnchor.constraint(equalTo: storageCard.leadingAnchor, constant: 16),
            storageBar.trailingAnchor.constraint(equalTo: storageCard.trailingAnchor, constant: -16),
            storageBar.heightAnchor.constraint(equalToConstant: 18),

            storageText.topAnchor.constraint(equalTo: storageBar.bottomAnchor, constant: 8),
            storageText.leadingAnchor.constraint(equalTo: storageCard.leadingAnchor, constant: 16),
            storageText.trailingAnchor.constraint(equalTo: storageCard.trailingAnchor, constant: -16),
            storageText.bottomAnchor.constraint(equalTo: storageCard.bottomAnchor, constant: -14),
        ])
    }

    private func setupSMARTCard() {
        let title = NSTextField(labelWithString: "S.M.A.R.T. NVMe HEALTH ATTRIBUTES")
        title.font = .systemFont(ofSize: 10, weight: .bold)
        title.textColor = .tertiaryLabelColor
        title.translatesAutoresizingMaskIntoConstraints = false

        smartGrid.translatesAutoresizingMaskIntoConstraints = false

        smartCard.addSubview(title)
        smartCard.addSubview(smartGrid)

        smartGrid.setStats([
            ("Drive Health", "—"),       ("Drive Temperature", "—"),   ("Total Data Written", "—"),
            ("Total Data Read", "—"),    ("Available Spare", "—"),     ("Power-On Hours", "—"),
            ("Power Cycles", "—"),       ("Unsafe Shutdowns", "—"),    ("Data Integrity Errors", "—")
        ])

        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: smartCard.topAnchor, constant: 14),
            title.leadingAnchor.constraint(equalTo: smartCard.leadingAnchor, constant: 16),

            smartGrid.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 12),
            smartGrid.leadingAnchor.constraint(equalTo: smartCard.leadingAnchor, constant: 16),
            smartGrid.trailingAnchor.constraint(equalTo: smartCard.trailingAnchor, constant: -16),
            smartGrid.bottomAnchor.constraint(equalTo: smartCard.bottomAnchor, constant: -16),
        ])
    }

    func update(data: DiskSMARTData) {
        driveModelLabel.stringValue = data.model
        let sizeStr = ByteCountFormatter.string(fromByteCount: data.sizeBytes, countStyle: .file)
        protocolLabel.stringValue = "\(data.protocolName) · \(sizeStr) Solid-State Drive"

        let isVerified = data.smartStatus.lowercased() == "verified"
        smartBadge.stringValue = "  S.M.A.R.T. \(data.smartStatus)  "
        smartBadge.textColor = isVerified ? .systemGreen : .systemRed
        smartBadge.layer?.backgroundColor = isVerified
            ? NSColor.systemGreen.withAlphaComponent(0.12).cgColor
            : NSColor.systemRed.withAlphaComponent(0.12).cgColor

        // Storage Bar
        if data.volumeTotalBytes > 0 {
            let used = data.volumeTotalBytes - data.volumeFreeBytes
            let usedFraction = Double(used) / Double(data.volumeTotalBytes)
            storageBar.segments = [
                (NSColor.systemBlue, usedFraction)
            ]
            let usedStr = ByteCountFormatter.string(fromByteCount: used, countStyle: .file)
            let freeStr = ByteCountFormatter.string(fromByteCount: data.volumeFreeBytes, countStyle: .file)
            let totalStr = ByteCountFormatter.string(fromByteCount: data.volumeTotalBytes, countStyle: .file)
            storageText.stringValue = "\(usedStr) Used · \(freeStr) Free of \(totalStr) (\(Int(usedFraction * 100))% used)"
        }

        // SMART Grid
        let healthStr = data.healthRemainingPercent.map { "\($0)% (Healthy)" } ?? "Good"
        let tempStr = data.temperatureCelsius.map { String(format: "%.1f°C", $0) } ?? "Normal"
        let writtenStr = data.dataUnitsWrittenTB.map { String(format: "%.2f TB", $0) } ?? "N/A"
        let readStr = data.dataUnitsReadTB.map { String(format: "%.2f TB", $0) } ?? "N/A"
        let spareStr = data.availableSparePercent.map { "\($0)% (Spare)" } ?? "100%"
        let hoursStr = data.powerOnHours.map { "\($0) hrs (\($0 / 24)d)" } ?? "N/A"
        let cyclesStr = data.powerCycles.map { "\($0) cycles" } ?? "N/A"
        let unsafeStr = data.unsafeShutdowns.map { "\($0)" } ?? "0"
        let errStr = data.mediaErrors.map { "\($0)" } ?? "0 (Clean)"

        smartGrid.setStats([
            ("Drive Health", healthStr),
            ("Drive Temperature", tempStr),
            ("Total Data Written", writtenStr),
            ("Total Data Read", readStr),
            ("Available Spare", spareStr),
            ("Power-On Hours", hoursStr),
            ("Power Cycles", cyclesStr),
            ("Unsafe Shutdowns", unsafeStr),
            ("Data Integrity Errors", errStr),
        ])
    }
}

// MARK: - Shared UI Helpers

private final class DetailHeader: NSView {
    private let titleLbl = NSTextField(labelWithString: "")
    private let subtitleLbl = NSTextField(labelWithString: "")
    var subtitle: String { get { subtitleLbl.stringValue } set { subtitleLbl.stringValue = newValue } }

    init(title: String, subtitle: String) {
        super.init(frame: .zero)
        titleLbl.stringValue = title; titleLbl.font = .systemFont(ofSize: 22, weight: .bold)
        titleLbl.lineBreakMode = .byTruncatingTail
        subtitleLbl.stringValue = subtitle
        subtitleLbl.font = .systemFont(ofSize: 12); subtitleLbl.textColor = .secondaryLabelColor
        subtitleLbl.lineBreakMode = .byTruncatingTail
        [titleLbl, subtitleLbl].forEach { $0.translatesAutoresizingMaskIntoConstraints = false; addSubview($0) }
        NSLayoutConstraint.activate([
            titleLbl.topAnchor.constraint(equalTo: topAnchor),
            titleLbl.leadingAnchor.constraint(equalTo: leadingAnchor),
            titleLbl.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor),
            subtitleLbl.topAnchor.constraint(equalTo: titleLbl.bottomAnchor, constant: 2),
            subtitleLbl.leadingAnchor.constraint(equalTo: leadingAnchor),
            subtitleLbl.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor),
            subtitleLbl.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
    }
    required init?(coder: NSCoder) { fatalError() }
}

private final class StatGrid: NSView {
    private let cols: Int
    private var labels: [(NSTextField, NSTextField)] = []
    private var gridConstraints: [NSLayoutConstraint] = []

    init(cols: Int) { self.cols = max(1, cols); super.init(frame: .zero) }
    required init?(coder: NSCoder) { fatalError() }

    func setStats(_ pairs: [(String, String)]) {
        if labels.count == pairs.count {
            for (i, (_, val)) in pairs.enumerated() {
                labels[i].1.stringValue = val
            }
            return
        }
        subviews.forEach { $0.removeFromSuperview() }
        labels = []
        NSLayoutConstraint.deactivate(gridConstraints)
        gridConstraints = []

        let rows = Int(ceil(Double(pairs.count) / Double(cols)))
        var rowContainers: [NSView] = []

        for r in 0..<rows {
            let rowView = NSView()
            rowView.translatesAutoresizingMaskIntoConstraints = false
            addSubview(rowView)
            rowContainers.append(rowView)

            gridConstraints.append(rowView.leadingAnchor.constraint(equalTo: leadingAnchor))
            gridConstraints.append(rowView.trailingAnchor.constraint(equalTo: trailingAnchor))

            if r == 0 {
                gridConstraints.append(rowView.topAnchor.constraint(equalTo: topAnchor))
            } else {
                let prev = rowContainers[r - 1]
                gridConstraints.append(rowView.topAnchor.constraint(equalTo: prev.bottomAnchor, constant: 14))
            }
            if r == rows - 1 {
                gridConstraints.append(rowView.bottomAnchor.constraint(equalTo: bottomAnchor))
            }

            var cellViews: [NSView] = []
            for c in 0..<cols {
                let idx = r * cols + c
                let cell = NSView()
                cell.translatesAutoresizingMaskIntoConstraints = false
                rowView.addSubview(cell)
                cellViews.append(cell)

                if idx < pairs.count {
                    let (key, val) = pairs[idx]
                    let kl = NSTextField(labelWithString: key)
                    kl.font = .systemFont(ofSize: 10, weight: .semibold)
                    kl.textColor = .secondaryLabelColor
                    kl.lineBreakMode = .byTruncatingTail
                    kl.translatesAutoresizingMaskIntoConstraints = false

                    let vl = NSTextField(labelWithString: val)
                    vl.font = .monospacedDigitSystemFont(ofSize: 13, weight: .medium)
                    vl.textColor = .labelColor
                    vl.lineBreakMode = .byTruncatingTail
                    vl.translatesAutoresizingMaskIntoConstraints = false

                    cell.addSubview(kl)
                    cell.addSubview(vl)

                    gridConstraints.append(contentsOf: [
                        kl.topAnchor.constraint(equalTo: cell.topAnchor),
                        kl.leadingAnchor.constraint(equalTo: cell.leadingAnchor),
                        kl.trailingAnchor.constraint(lessThanOrEqualTo: cell.trailingAnchor),

                        vl.topAnchor.constraint(equalTo: kl.bottomAnchor, constant: 2),
                        vl.leadingAnchor.constraint(equalTo: cell.leadingAnchor),
                        vl.trailingAnchor.constraint(lessThanOrEqualTo: cell.trailingAnchor),
                        vl.bottomAnchor.constraint(equalTo: cell.bottomAnchor)
                    ])
                    labels.append((kl, vl))
                }

                gridConstraints.append(cell.topAnchor.constraint(equalTo: rowView.topAnchor))
                gridConstraints.append(cell.bottomAnchor.constraint(equalTo: rowView.bottomAnchor))
            }

            for (c, cell) in cellViews.enumerated() {
                if c == 0 {
                    gridConstraints.append(cell.leadingAnchor.constraint(equalTo: rowView.leadingAnchor))
                } else {
                    let prevCell = cellViews[c - 1]
                    gridConstraints.append(cell.leadingAnchor.constraint(equalTo: prevCell.trailingAnchor, constant: 16))
                    gridConstraints.append(cell.widthAnchor.constraint(equalTo: cellViews[0].widthAnchor))
                }
                if c == cellViews.count - 1 {
                    gridConstraints.append(cell.trailingAnchor.constraint(equalTo: rowView.trailingAnchor))
                }
            }
        }
        NSLayoutConstraint.activate(gridConstraints)
    }
}

private final class MemoryBarView: NSView {
    var segments: [(NSColor, Double)] = [] { didSet { needsDisplay = true } }
    override init(frame: NSRect) { super.init(frame: frame); wantsLayer = true; layer?.cornerRadius = 5; layer?.masksToBounds = true }
    required init?(coder: NSCoder) { fatalError() }
    override func draw(_ dirty: NSRect) {
        super.draw(dirty); let b = bounds; var x = b.minX
        for (color, frac) in segments {
            let w = b.width * CGFloat(min(1, max(0, frac)))
            let r = NSRect(x: x, y: b.minY, width: w, height: b.height)
            color.setFill(); NSBezierPath(rect: r).fill(); x += w
        }
        if x < b.maxX {
            NSColor.separatorColor.withAlphaComponent(0.2).setFill()
            NSBezierPath(rect: NSRect(x: x, y: b.minY, width: b.maxX - x, height: b.height)).fill()
        }
    }
}

private final class MemoryLegendView: NSView {
    var segments: [(NSColor, String)] = [] { didSet { rebuild() } }
    private var stack: NSStackView?
    override init(frame: NSRect) { super.init(frame: frame) }
    required init?(coder: NSCoder) { fatalError() }
    private func rebuild() {
        stack?.removeFromSuperview()
        let s = NSStackView(); s.orientation = .horizontal; s.spacing = 16; s.translatesAutoresizingMaskIntoConstraints = false
        for (color, label) in segments {
            let dot = NSView(); dot.wantsLayer = true; dot.layer?.cornerRadius = 4
            dot.layer?.backgroundColor = color.cgColor; dot.translatesAutoresizingMaskIntoConstraints = false
            dot.widthAnchor.constraint(equalToConstant: 8).isActive = true
            dot.heightAnchor.constraint(equalToConstant: 8).isActive = true
            let lbl = NSTextField(labelWithString: label)
            lbl.font = .systemFont(ofSize: 10); lbl.textColor = .secondaryLabelColor
            let pair = NSStackView(views: [dot, lbl]); pair.spacing = 4; pair.alignment = .centerY
            s.addArrangedSubview(pair)
        }
        addSubview(s); stack = s
        NSLayoutConstraint.activate([
            s.leadingAnchor.constraint(equalTo: leadingAnchor),
            s.centerYAnchor.constraint(equalTo: centerYAnchor)])
    }
}

private final class DualSparklineView: NSView {
    private var values1: [Double] = []; private var values2: [Double] = []
    private let color1: NSColor; private let color2: NSColor
    private let label1: String; private let label2: String

    init(color1: NSColor, color2: NSColor, label1: String, label2: String) {
        self.color1 = color1; self.color2 = color2
        self.label1 = label1; self.label2 = label2
        super.init(frame: .zero); wantsLayer = true; buildLegend()
    }
    required init?(coder: NSCoder) { fatalError() }

    private func buildLegend() {
        func dot(_ c: NSColor) -> NSView {
            let v = NSView(); v.wantsLayer = true; v.layer?.backgroundColor = c.cgColor
            v.layer?.cornerRadius = 3
            v.translatesAutoresizingMaskIntoConstraints = false
            v.widthAnchor.constraint(equalToConstant: 6).isActive = true
            v.heightAnchor.constraint(equalToConstant: 6).isActive = true
            return v
        }
        let d1 = dot(color1); let l1 = NSTextField(labelWithString: label1)
        l1.font = .systemFont(ofSize: 10); l1.textColor = color1; l1.translatesAutoresizingMaskIntoConstraints = false
        let d2 = dot(color2); let l2 = NSTextField(labelWithString: label2)
        l2.font = .systemFont(ofSize: 10); l2.textColor = color2; l2.translatesAutoresizingMaskIntoConstraints = false
        let p1 = NSStackView(views: [d1, l1]); p1.spacing = 4; p1.alignment = .centerY
        let p2 = NSStackView(views: [d2, l2]); p2.spacing = 4; p2.alignment = .centerY
        let stack = NSStackView(views: [p1, p2]); stack.spacing = 14; stack.alignment = .centerY
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.topAnchor.constraint(equalTo: topAnchor),
        ])
    }

    func set(values1 v1: [Double], values2 v2: [Double]) { values1 = v1; values2 = v2; needsDisplay = true }

    override func draw(_ dirty: NSRect) {
        super.draw(dirty)
        let b = bounds.insetBy(dx: 2, dy: 20).offsetBy(dx: 0, dy: -8)
        guard b.width > 4, b.height > 4 else { return }

        let grid = NSBezierPath(); grid.lineWidth = 0.5
        for f: CGFloat in [0.25, 0.5, 0.75] {
            let y = b.minY + b.height * f
            grid.move(to: NSPoint(x: b.minX, y: y)); grid.line(to: NSPoint(x: b.maxX, y: y))
        }
        NSColor.separatorColor.withAlphaComponent(0.18).setStroke(); grid.stroke()

        func drawLine(_ vals: [Double], _ color: NSColor) {
            guard vals.count > 1 else { return }
            let mx = (vals.max() ?? 1) * 1.2
            let pts: [NSPoint] = vals.enumerated().map { (i, v) in
                let x = b.minX + b.width * CGFloat(i) / CGFloat(vals.count - 1)
                let y = b.minY + b.height * CGFloat(min(1, max(0, v / max(mx, 0.001))))
                return NSPoint(x: x, y: y)
            }
            let path = NSBezierPath(); path.lineWidth = 1.5
            path.lineJoinStyle = .round; path.lineCapStyle = .round
            path.move(to: pts[0])
            for i in 1..<pts.count { path.line(to: pts[i]) }

            let fill = path.copy() as! NSBezierPath
            fill.line(to: NSPoint(x: pts.last!.x, y: b.minY))
            fill.line(to: NSPoint(x: pts.first!.x, y: b.minY)); fill.close()
            color.withAlphaComponent(0.1).setFill(); fill.fill()

            color.setStroke(); path.stroke()
        }
        drawLine(values1, color1); drawLine(values2, color2)
    }
}

private final class MiniSparklineView: NSView {
    var values: [Double] = [] { didSet { needsDisplay = true } }
    var lineColor: NSColor = .systemBlue
    var maximum: Double = 100

    override init(frame: NSRect) { super.init(frame: frame); wantsLayer = true }
    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ dirty: NSRect) {
        super.draw(dirty)
        let b = bounds.insetBy(dx: 1, dy: 2)
        guard b.width > 2, b.height > 2, values.count > 1 else { return }
        let pts: [NSPoint] = values.enumerated().map { (i, v) in
            let x = b.minX + b.width * CGFloat(i) / CGFloat(values.count - 1)
            let y = b.minY + b.height * CGFloat(min(1, max(0, v / max(maximum, 0.001))))
            return NSPoint(x: x, y: y)
        }
        let path = NSBezierPath(); path.lineWidth = 1.5
        path.move(to: pts[0]); for i in 1..<pts.count { path.line(to: pts[i]) }
        let fill = path.copy() as! NSBezierPath
        fill.line(to: NSPoint(x: pts.last!.x, y: b.minY))
        fill.line(to: NSPoint(x: pts.first!.x, y: b.minY)); fill.close()
        lineColor.withAlphaComponent(0.12).setFill(); fill.fill()
        lineColor.setStroke(); path.stroke()
    }
}

private final class SparklineView: NSView {
    var values: [Double] = [] { didSet { needsDisplay = true } }
    private let color: NSColor; private let fill: NSColor; private let maxVal: Double

    init(color: NSColor, fill: NSColor, max: Double) {
        self.color = color; self.fill = fill; self.maxVal = max
        super.init(frame: .zero); wantsLayer = true
    }
    required init?(coder: NSCoder) { fatalError() }

    override func draw(_ dirty: NSRect) {
        super.draw(dirty)
        let b = bounds.insetBy(dx: 2, dy: 6)
        guard b.width > 4, b.height > 4 else { return }

        let grid = NSBezierPath(); grid.lineWidth = 0.5
        for f: CGFloat in [0.25, 0.5, 0.75] {
            let y = b.minY + b.height * f
            grid.move(to: .init(x: b.minX, y: y)); grid.line(to: .init(x: b.maxX, y: y))
        }
        NSColor.separatorColor.withAlphaComponent(0.2).setStroke(); grid.stroke()

        guard values.count > 1 else { return }
        let pts: [NSPoint] = values.enumerated().map { (i, v) in
            let x = b.minX + b.width * CGFloat(i) / CGFloat(values.count - 1)
            let y = b.minY + b.height * CGFloat(min(1, max(0, v / max(maxVal, 0.001))))
            return .init(x: x, y: y)
        }

        let path = NSBezierPath(); path.lineWidth = 2
        path.lineJoinStyle = .round; path.lineCapStyle = .round
        path.move(to: pts[0])
        let t: CGFloat = 0.3
        for i in 1..<pts.count {
            let p0 = pts[max(0, i-2)]; let p1 = pts[i-1]; let p2 = pts[i]
            let p3 = pts[min(pts.count-1, i+1)]
            let cp1 = NSPoint(x: p1.x + (p2.x-p0.x)*t, y: p1.y + (p2.y-p0.y)*t)
            let cp2 = NSPoint(x: p2.x - (p3.x-p1.x)*t, y: p2.y - (p3.y-p1.y)*t)
            path.curve(to: p2, controlPoint1: cp1, controlPoint2: cp2)
        }

        let fp = path.copy() as! NSBezierPath
        fp.line(to: .init(x: pts.last!.x, y: b.minY))
        fp.line(to: .init(x: pts.first!.x, y: b.minY)); fp.close()
        fill.setFill(); fp.fill()

        color.setStroke(); path.stroke()

        if let last = pts.last {
            let dot = NSBezierPath(ovalIn: .init(x: last.x-3, y: last.y-3, width: 6, height: 6))
            color.setFill(); NSColor.windowBackgroundColor.withAlphaComponent(0.8).setStroke()
            dot.lineWidth = 1.5; dot.fill(); dot.stroke()
        }
    }
}
