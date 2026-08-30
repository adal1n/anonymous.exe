import { Client } from "adb-ts"
import Logger from "electron-log"
import * as frida from "frida"
import { existsSync } from "fs"
import * as path from "path"

// Bundled binaries (scripts/fetch-binaries.cjs → bin/, shipped via
// electron-builder extraResources). Resolve across dev and packaged layouts;
// fall back to whatever is on PATH / the device so nothing breaks if the
// bundle is ever absent.
const binCandidates = (...segments:string[]):string[] => {
    const dirs = [
        process.resourcesPath ? path.join(process.resourcesPath, "bin") : "",
        path.join(__dirname, "..", "..", "bin"),
        path.join(__dirname, "..", "..", "..", "bin"),
    ].filter(Boolean)
    return dirs.map(d => path.join(d, ...segments))
}

const resolveBin = (...segments:string[]):string => {
    for (const p of binCandidates(...segments)) {
        if (existsSync(p)) return p
    }
    return ""
}

const adbBin = resolveBin("adb", "adb.exe")

export const fridaServerBin = (version:string, arch:string):string =>
    resolveBin("frida-server", `frida-server-${version}-android-${arch}`)

export const adb = new Client(adbBin ? { bin: adbBin } : {})

export const pushFile = (id:string, src:string, dest:string):Promise<void> =>
    new Promise(async (resolve, reject) => {
        try {
            const transfer = await adb.push(id, src, dest)
            transfer.on("end", () => resolve())
            transfer.on("error", reject)
        } catch (err) {
            reject(err)
        }
    })

export const getUrl = (version:string, arch:string) => `https://github.com/frida/frida/releases/download/${version}/${fileName(version, arch)}.xz`
export const fileNameFB = (version:string, arch:string) => `frida-server-${version}-freebsd-${arch}`
export const fileName = (version:string, arch:string) => `frida-server-${version}-android-${arch}`
export const getArch = async (id:string):Promise<string> => {
    if(id === '') {
        Logger.error('[*] ADB not connected')
        return ''
    }
    const os = await adb.shell(id, 'getprop ro.product.cpu.abi')
    let arch = 'arm'
    if (os.includes('x86')) {
        arch = 'x86'
    }
    const bits = await adb.shell(id, 'getprop ro.product.cpu.abilist')
    if (bits.includes('64')) {
        if(arch === 'x86') arch = 'x86_64'
        else arch = 'arm64'
    }
    return arch
}

// `su` is missing (or refuses) on locked-down emulators — PC-cafe BlueStacks
// images ship with root off — and on stock phones. frida-server itself needs
// root, so recognise that failure text and report it instead of letting the
// run die later with a generic "failed to connect".
export const NO_ROOT_REASON = 'No root on device — enable root in the emulator settings'

const looksLikeNoRoot = (output:string):boolean =>
    /su: (not found|inaccessible)|not found|permission denied|need to be root|access denied/i.test(output)

// A frida-server that exits immediately almost always says why. Keep the
// device's own words in the failure state — a bare "Frida server crashed"
// tells nobody anything, and the log is the only other place it survives.
const exitReason = (output:string):string => {
    const text = String(output ?? '')
    if (looksLikeNoRoot(text)) return NO_ROOT_REASON
    if (/address already in use|unable to bind|already running/i.test(text))
        return 'frida-server is already running — restart the emulator and try again'
    if (/exec format error|not executable|cannot execute/i.test(text))
        return 'frida-server does not match the device CPU — delete /data/local/tmp/frida-server* and retry'
    const detail = text.split('\n').map(l => l.trim()).filter(Boolean).pop() ?? ''
    if (detail === '') return ''
    return `Frida server crashed: ${detail.length > 120 ? detail.slice(0, 120) + '…' : detail}`
}

export const hasRoot = async (id:string):Promise<boolean> => {
    if(id === '') return false
    try {
        const out = await adb.shell(id, 'su -c id')
        return String(out).includes('uid=0')
    } catch (err) {
        Logger.error(`[*] Root check failed: ${err}`)
        return false
    }
}

export const startFrida = async (id:string, filename:string, onCrashed:(reason?:string) => void):Promise<boolean> => {
    if(id === '') {
        Logger.error('[*] ADB not connected');
        return false;
    }
    try{
        const server = adb.shell(id, `su -c /data/local/tmp/${filename}`)
        // frida-server only returns when it exits, so this resolving at all
        // means the server is gone — either it crashed or `su` rejected it.
        server.then(out => {
            const text = String(out ?? '')
            if(text.trim() !== '') Logger.error(`[*] frida-server exited: ${text.trim()}`)
            onCrashed(exitReason(text) || undefined)
        }).catch(err => {
            Logger.error(`[*] frida-server exited with an error: ${err}`)
            onCrashed(exitReason(String(err)) || undefined)
        })
        return true
    } catch (err) {
        Logger.error(`[*] Failed to start frida server`)
        return false
    }
}

const delay = (ms:number):Promise<void> => new Promise(resolve => setTimeout(resolve, ms))

// Per-attempt wait for frida.getDevice() and total connect attempts. frida-server
// often needs a moment after start before the device is enumerable, so we wait
// (timeout) and retry with backoff rather than failing on the first miss.
const FRIDA_DEVICE_TIMEOUT = 5000
const FRIDA_CONNECT_ATTEMPTS = 4

// Resolve a usable frida Device for the given adb serial. Tries, in order:
//   1. getDevice(serial) — frida enumerates adb-attached emulators with id === serial
//   2. enumerateDevices() — exact id match, then any usb/remote device as fallback
//   3. addRemoteDevice(serial) — frida-server exposed directly over TCP
// Each strategy is bounded and retried, so a transient miss never hangs forever.
const resolveFridaDevice = async (serial:string):Promise<frida.Device | null> => {
    const deviceManager = frida.getDeviceManager()
    for (let attempt = 1; attempt <= FRIDA_CONNECT_ATTEMPTS; attempt++) {
        // 1. Wait up to FRIDA_DEVICE_TIMEOUT for the device to appear by id.
        try {
            const device = await frida.getDevice(serial, { timeout: FRIDA_DEVICE_TIMEOUT })
            if (device) return device
        } catch (err) {
            Logger.warn(`[*] Frida getDevice attempt ${attempt} failed: ${err}`)
        }
        // 2. Fall back to scanning what's currently enumerated.
        try {
            const devices = await deviceManager.enumerateDevices()
            const match = devices.find(d => d.id === serial)
                ?? devices.find(d => d.type === frida.DeviceType.Usb)
                ?? devices.find(d => d.type === frida.DeviceType.Remote)
            if (match) return match
        } catch (err) {
            Logger.warn(`[*] Frida enumerateDevices attempt ${attempt} failed: ${err}`)
        }
        // 3. Last resort: connect to a frida-server listening over TCP.
        try {
            const remote = await deviceManager.addRemoteDevice(serial)
            if (remote) return remote
        } catch (err) {
            Logger.warn(`[*] Frida addRemoteDevice attempt ${attempt} failed: ${err}`)
        }
        if (attempt < FRIDA_CONNECT_ATTEMPTS) await delay(800 * attempt)
    }
    return null
}

export const connectFrida = async (
    serial:string,
    onCrashed:() => void,
    onConnected:(d:frida.Device | null) => void
) => {
    const device = await resolveFridaDevice(serial)
    if (!device) {
        Logger.error(`[*] Frida device not connected to ${serial}`)
        onConnected(null)
        return
    }
    // Reconnects reuse the same Device object, so drop any prior handler before
    // re-adding to avoid stacking duplicate crash callbacks.
    try { device.processCrashed.disconnect(onCrashed) } catch (_) {}
    device.processCrashed.connect(onCrashed)
    Logger.info(`[*] Frida connected to ${serial} (${device.id})`)
    onConnected(device)
}

// Backward compatibility export (to be removed after refactor)
export const conenctFrida = connectFrida;

export const connectAdbDevice = async (serial:string):Promise<string> => {
    try{
        await adb.disconnect(serial);
    } catch (_) {};
    const result = await adb.connect(serial);
    if (!result) {
        Logger.error('[*] Failed to connect to adb server')
        return ''
    }
    return result
}

const isOnlineState = (d:any):boolean => (d?.state ?? d?.type) === 'device'

// Best-effort: adb-ts exposes listDevices(), but tolerate API/typing drift —
// callers must not hard-depend on this returning anything.
export const listAdbDevices = async ():Promise<string[]> => {
    try {
        const devices = await (adb as any).listDevices()
        if (!Array.isArray(devices)) return []
        return devices.filter(isOnlineState).map((d:any) => d.id)
    } catch (err) {
        Logger.error(`[*] Failed to list adb devices: ${err}`)
        return []
    }
}

// Reliable connectivity probe using an API the codebase already relies on.
const adbResponsive = async (serial:string):Promise<boolean> => {
    try {
        const out = await adb.shell(serial, 'echo pixel_ok')
        return typeof out === 'string' && out.includes('pixel_ok')
    } catch (_) {
        return false
    }
}

// BlueStacks 5 exposes ADB on 5555 by default; extra instances use a dynamic
// port in the 556x–569x range. We probe these so an install-only user never
// has to hunt for the port — they just click "Connect ADB".
const BLUESTACKS_PORTS = [
    5555, 5556, 5565, 5575, 5585, 5595,
    5605, 5615, 5625, 5635, 5645, 5665, 5685,
]

export const autoConnectAdb = async (preferred:string):Promise<string> => {
    // 1. Anything already attached (running emulator / prior adb connect) wins.
    const existing = await listAdbDevices()
    if (existing.length > 0) {
        const pick = (preferred && existing.includes(preferred.trim()))
            ? preferred.trim()
            : existing[0]
        if (await adbResponsive(pick)) {
            Logger.info(`[*] ADB device already connected: ${pick}`)
            return pick
        }
    }
    // 2. Probe the user-supplied serial first, then common BlueStacks ports.
    const candidates:string[] = []
    if (preferred && preferred.trim()) candidates.push(preferred.trim())
    for (const port of BLUESTACKS_PORTS) {
        const s = `127.0.0.1:${port}`
        if (!candidates.includes(s)) candidates.push(s)
    }
    for (const serial of candidates) {
        try {
            const id = await connectAdbDevice(serial)
            if (id === '') continue
            if (await adbResponsive(serial)) {
                Logger.info(`[*] ADB auto-connected to ${serial}`)
                return serial
            }
        } catch (_) { /* port not listening — try next */ }
    }
    Logger.error('[*] ADB auto-connect failed for all candidates')
    return ''
}

export const fileExist = async (id:string, version:string):Promise<string> => {
    if(id === '') {
        Logger.error('[*] ADB not connected');
        return '';
    }
    const files = await adb.readDir(id, '/data/local/tmp');
    const arch = await getArch(id);
    const file = files.find(file => ["frida", "frida-server", fileName(version, arch), fileNameFB(version, arch)].includes(file.name))
    if (!file) {
        Logger.error('[*] Frida server not found')
        return ""
    }
    return file.name
}

// Result of the pre-launch permission check. `reason` is shown to the user as
// the failure state, so it has to name the actual problem.
export type PermCheck = { ok:boolean, reason:string }

export const checkFridaPerm = async (id:string, filename:string):Promise<PermCheck> => {
    if(id === '') {
        Logger.error('[*] ADB not connected');
        return { ok: false, reason: 'ADB not connected' };
    }
    const target = `/data/local/tmp/${filename}`

    // First field of `ls -l` is the mode string, e.g. "-rwxrwxrwx".
    const mode = async ():Promise<string> => {
        try {
            const out = String(await adb.shell(id, `ls -l ${target}`)).trim()
            if (/no such file/i.test(out)) return ''
            return out.split(/\s+/)[0] ?? ''
        } catch (err) {
            Logger.error(`[*] Failed to stat ${target}: ${err}`)
            return ''
        }
    }

    const executable = (m:string):boolean => /^-rwx/.test(m)

    let perms = await mode()
    if (perms === '') return { ok: false, reason: 'frida-server missing on device' }
    if (executable(perms)) return { ok: true, reason: '' }

    // The binary is pushed over adb, so it belongs to the shell user and can be
    // chmod'ed without root — only fall back to `su` if the plain chmod fails.
    for (const cmd of [`chmod 777 ${target}`, `su -c "chmod 777 ${target}"`]) {
        try {
            await adb.shell(id, cmd)
        } catch (err) {
            Logger.error(`[*] ${cmd} failed: ${err}`)
            continue
        }
        perms = await mode()
        if (executable(perms)) return { ok: true, reason: '' }
    }

    Logger.error(`[*] Could not make ${target} executable (mode=${perms || 'unknown'})`)
    return {
        ok: false,
        reason: await hasRoot(id) ? 'Failed to chmod frida-server' : NO_ROOT_REASON,
    }
}

export const executeProcess = async (
    process:string,
    device:frida.Device,
    _script:string,
    recieveCallback:(message: frida.Message, data: Buffer | null) => void,
    attachCallback:() => void,
    disposeCallback:() => void,
    useEmulator:boolean = false
):Promise<[
    () => Promise<void>,
    frida.Script,
    number | null
]> => {
    const pid = await device.spawn([process])
    const session = await device.attach(pid, { realm: useEmulator ? frida.Realm.Emulated : frida.Realm.Native })
    Logger.info(`[*] Process attached`)
    const script = await session.createScript(_script)
    await script.load()
    await session.resume()
    await device.resume(pid)
    Logger.info(`[*] Session resumed`)
    attachCallback()
    script.message.connect(recieveCallback)
    session.detached.connect(disposeCallback)
    const dispose = async () => {
        script.message.disconnect(recieveCallback)
        session.detached.disconnect(disposeCallback)
        await session.detach()
    }
    return [dispose, script, pid]
}

export const attachProcess = async (
    pid:number,
    device:frida.Device,
    _script:string,
    recieveCallback:(message: frida.Message, data: Buffer | null) => void,
    attachCallback:() => void,
    disposeCallback:() => void,
    useEmulator:boolean = false
):Promise<[
    () => Promise<void>,
    frida.Script
]> => {
    if (!pid) {
        Logger.error(`[*] Process not found`)
        return [async () => {}, null]
    }
    const session = await device.attach(pid, { realm: useEmulator ? frida.Realm.Emulated : frida.Realm.Native })
    const script = await session.createScript(_script)
    await script.load()
    attachCallback()
    script.message.connect(recieveCallback)
    session.detached.connect(disposeCallback)
    const dispose = async () => {
        script.message.disconnect(recieveCallback)
        session.detached.disconnect(disposeCallback)
        await session.detach()
    }
    return [dispose, script]
}