import type { AddonReleaseCheck, AnalysisCheck, AnalyzeRequest, CcuDevice, CcuMasterdataPayload, CcuSnapshot, CentralReleaseCheck, CollectorPayload, Evidence, ReleaseCheck, SnifferDeviceSummary, SnifferSnapshot } from "./types.js";
import { isBenignLogLine, isClearingEventLine } from "./aiLogAnalyzer.js";
import { describeKnownService } from "./networkIdentity.js";
import { buildRoutingTopology, parseRadioGateways } from "./routingTopology.js";

const now = () => new Date().toISOString();
const xmlApiInstallUrl = "https://github.com/homematic-community/XML-API";

function normalizeHostForSecurity(host?: string): string {
  if (!host) return "";

  try {
    return new URL(/^https?:\/\//i.test(host) ? host : `http://${host}`).hostname.toLowerCase();
  } catch {
    return host.split("/")[0]?.split(":")[0]?.toLowerCase() ?? "";
  }
}

function isPrivateIp(host: string): boolean {
  const parts = host.split(".").map((part) => Number(part));

  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }

  const [first, second] = parts;

  return first === 10
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168)
    || (first === 169 && second === 254)
    || first === 127;
}

function isLocalOrPrivateHost(host?: string): boolean {
  const normalizedHost = normalizeHostForSecurity(host);

  if (!normalizedHost) return true;
  if (normalizedHost === "localhost") return true;
  if (normalizedHost.endsWith(".local")) return true;
  if (normalizedHost.endsWith(".fritz.box")) return true;
  if (normalizedHost.includes(":")) return normalizedHost === "::1" || normalizedHost.startsWith("fe80:");

  return isPrivateIp(normalizedHost);
}

function ccuConnectionSummary(ccu?: CcuSnapshot): string {
  if (!ccu) return "Vom Analyzer-Server liegt noch kein Verbindungstest vor.";
  if (ccu.webUiReachable) {
    return "Die CCU-WebUI antwortet dem Analyzer-Server, aber die XML-API-Gerätedaten konnten nicht gelesen werden.";
  }

  return "Der Analyzer-Server konnte die eingetragene CCU-Adresse nicht erreichen. Das kann sich von deinem Browser unterscheiden.";
}

function ccuConnectionRecommendation(ccu?: CcuSnapshot): string {
  switch (ccu?.errorCode) {
    case "dns":
      return "Verwende im Setup testweise die lokale IP-Adresse der CCU statt eines Hostnamens. Prüfe außerdem die DNS-Einstellungen des Analyzer-Servers/LXC.";
    case "timeout":
      return ccu?.webUiReachable
        ? "Die CCU-WebUI ist erreichbar, aber die XML-API-Geräteliste antwortet zu langsam oder hängt. Starte die Analyse erneut. Bleibt der Fehler bestehen, öffne `statelist.cgi` direkt und prüfe, ob die vollständige XML-Ausgabe innerhalb von 30 Sekunden erscheint."
        : "Prüfe vom Analyzer-System aus die Route zur CCU, Firewall-Regeln und bei Proxmox die Netzwerkfreigabe des LXC. Ein Browserzugriff von deinem PC beweist diesen Netzwerkweg nicht.";
    case "connection-refused":
      return "Prüfe Protokoll und Port im CCU-Host. Eventuell wurde HTTPS eingetragen, obwohl die CCU nur HTTP anbietet – oder umgekehrt.";
    case "network":
      return "Prüfe Routing und Firewall des Analyzer-Servers/LXC. Bei Proxmox muss der Container das lokale Netz der CCU erreichen dürfen.";
    case "tls":
      return "Der Analyzer-Server vertraut dem HTTPS-Zertifikat der CCU nicht. Nutze im lokalen, geschützten Netz testweise die HTTP-Adresse oder hinterlege ein vertrauenswürdiges Zertifikat.";
    case "authentication":
      return "Die CCU antwortet, lehnt aber die XML-API-Anmeldung ab. Prüfe besonders den XML-API-Token (`sid`); das WebUI-Passwort allein reicht bei XML-API v2 nicht.";
    case "xml-api-missing":
      return "Die CCU antwortet, aber der XML-API-Pfad wurde nicht gefunden. Prüfe Installation und Pfad des Add-ons.";
    case "empty-data":
      return "Die XML-API antwortet, liefert aber keine Geräteliste. Öffne `statelist.cgi` mit demselben Token und prüfe, ob dort Geräte enthalten sind.";
    case "http":
      return "Die CCU antwortet mit einem HTTP-Fehler. Prüfe den in den Belegen genannten Statuscode sowie Protokoll, Port und XML-API-Pfad.";
    default:
      return ccu?.webUiReachable
        ? "Die Netzwerkverbindung funktioniert. Prüfe nun XML-API-Token, Pfad und Add-on-Version."
        : "Teste die CCU-Adresse direkt vom Analyzer-Server/LXC aus und prüfe Netzwerk, Firewall, Protokoll und Port.";
  }
}

function ccuDiagnosticEvidence(ccu?: CcuSnapshot): Evidence[] {
  return (ccu?.diagnostics ?? []).map((diagnostic) => ({
    source: diagnostic.step,
    detail: `${diagnostic.status === "ok" ? "Erfolgreich" : diagnostic.status === "failed" ? "Fehlgeschlagen" : "Übersprungen"}: ${diagnostic.detail}`,
    timestamp: ccu?.collectedAt
  }));
}

function statusForCount(count: number, criticalAt = 1): "ok" | "critical" {
  return count >= criticalAt ? "critical" : "ok";
}

function isBatteryEvidence(evidence: Evidence): boolean {
  return /\b(?:LOWBAT|LOW_BAT|BATTERY_LOW)\b|batter(?:ie|y)/i.test(evidence.detail);
}

function isConfigPendingEvidence(evidence: Evidence): boolean {
  return /\b(?:CONFIG_PENDING|PENDING_CONFIG)\b|konfiguration\s+ausstehend/i.test(evidence.detail);
}

function evidenceFromDevices(devices: CcuDevice[], predicate: (device: CcuDevice) => boolean, max = 8): Evidence[] {
  return devices
    .filter(predicate)
    .flatMap((device) => device.evidence.length > 0
      ? device.evidence
      : [{ source: "CCU Gerätedaten", detail: `${device.name}: auffälliger Status wurde gemeldet.` }]
    )
    .slice(0, max);
}

function deviceNames(devices: CcuDevice[], predicate: (device: CcuDevice) => boolean): string {
  const names = devices.filter(predicate).map((device) => device.name).slice(0, 6);
  if (names.length === 0) return "";
  const suffix = devices.filter(predicate).length > names.length ? " …" : "";
  return `${names.join(", ")}${suffix}`;
}

function dutyCycleStatus(value: number | undefined): AnalysisCheck["status"] {
  if (value === undefined) return "unavailable";
  if (value >= 90) return "critical";
  if (value >= 70) return "warning";
  if (value >= 50) return "improvement";
  return "ok";
}

function dutyCycleText(value: number | undefined): string {
  return value === undefined ? "kein belegter Wert" : `${value}%`;
}

function collectorRecordValue(record: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = record?.[key];
  return value === undefined || value === null || value === "" ? undefined : String(value);
}

const ccuServicePorts = new Set(["80", "443", "8181", "2001", "2010", "9292", "42001", "42010", "8700", "8701"]);

const ccuServiceLabels: Record<string, string> = {
  "80": "WebUI/HTTP",
  "443": "WebUI/HTTPS",
  "8181": "XML-API/ReGa",
  "2001": "BidCos-RPC",
  "2010": "HmIP-RPC",
  "9292": "CUxD/XML-API",
  "42001": "HmIPServer",
  "42010": "HmIPServer",
  "8700": "ReGa/XML-RPC",
  "8701": "ReGa/XML-RPC"
};

type ExternalAccessCandidate = {
  host: string;
  hostname?: string;
  count: number;
  ports: string[];
  isPublic: boolean;
  states: string[];
  lines: string[];
};

type FirmwareDifference = {
  type: string;
  versions: string[];
  devices: string[];
};

type AvailableFirmwareUpdate = {
  name: string;
  address: string;
  type: string;
  installed: string;
  available: string;
  state?: string;
};

type LogAnalysis = {
  relevantLines: string[];
  noisyLines: string[];
  status: AnalysisCheck["status"];
};

function analyzeLogLines(logs: string[] | undefined): LogAnalysis {
  const lines = logs?.map((line) => line.trim()).filter(Boolean) ?? [];
  const noisyLines = lines.filter((line) => /\b(debug|verbose)\b/i.test(line));
  const relevantLines = lines.filter((line) => {
    const isNoise = /\b(debug|verbose)\b/i.test(line);
    const isRelevant = /\b(error|err|fatal|panic|warn|warning|failed|failure|timeout|unreach|sticky_unreach|lowbat|service unavailable|segfault|restart|crash|critical)\b/i.test(line);
    return isRelevant && !isNoise && !isClearingEventLine(line) && !isBenignLogLine(line);
  });
  const criticalLines = relevantLines.filter((line) => /\b(fatal|panic|segfault|crash|critical|service unavailable)\b/i.test(line));

  return {
    relevantLines,
    noisyLines,
    status: criticalLines.length > 0 ? "critical" : relevantLines.length > 0 ? "warning" : lines.length > 0 ? "ok" : "unavailable"
  };
}

function parseExternalAccesses(collector: CollectorPayload | undefined, ccuHost?: string, hostnames: Record<string, string> = {}): ExternalAccessCandidate[] {
  const lines = collector?.network?.connections ?? [];
  const ownHost = normalizeHostForSecurity(ccuHost);
  const grouped = new Map<string, { ports: Set<string>; states: Set<string>; lines: string[] }>();

  for (const line of lines) {
    const endpointMatches = [...line.matchAll(/((?:\d{1,3}\.){3}\d{1,3}|localhost):(\d{1,5})/g)];
    if (endpointMatches.length < 2) continue;

    const localPort = endpointMatches[0]?.[2];
    const remoteHost = endpointMatches[1]?.[1];
    if (!localPort || !remoteHost || !ccuServicePorts.has(localPort)) continue;
    if (remoteHost === "0.0.0.0" || remoteHost === "127.0.0.1" || remoteHost === "localhost" || remoteHost === ownHost) continue;

    const current = grouped.get(remoteHost) ?? { ports: new Set<string>(), states: new Set<string>(), lines: [] };
    current.ports.add(localPort);
    const rawState = line.match(/\b(ESTAB|ESTABLISHED|TIME_WAIT|CLOSE_WAIT|SYN_SENT|SYN_RECV|FIN_WAIT1|FIN_WAIT2|LAST_ACK)\b/i)?.[1]?.toUpperCase();
    if (rawState) current.states.add(rawState === "ESTAB" ? "ESTABLISHED" : rawState);
    current.lines.push(line);
    grouped.set(remoteHost, current);
  }

  return [...grouped.entries()]
    .map(([host, value]) => ({
      host,
      hostname: hostnames[host],
      count: value.lines.length,
      ports: [...value.ports].sort((firstPort, secondPort) => Number(firstPort) - Number(secondPort)),
      isPublic: !isLocalOrPrivateHost(host),
      states: [...value.states],
      lines: value.lines.slice(0, 4)
    }))
    .sort((firstCandidate, secondCandidate) => secondCandidate.count - firstCandidate.count);
}

function externalAccessDisplayName(access: ExternalAccessCandidate) {
  return access.hostname ? `${access.hostname} (${access.host})` : `${access.host} (DNS-Name nicht auflösbar)`;
}

function externalAccessSummary(access: ExternalAccessCandidate) {
  const services = access.ports.map((port) => ccuServiceLabels[port] ?? `Port ${port}`).join(", ");
  return `${externalAccessDisplayName(access)}: ${access.count} Verbindung${access.count === 1 ? "" : "en"} über ${services}`;
}

function findFirmwareDifferences(masterdata: CcuMasterdataPayload | undefined, ccu: CcuSnapshot | undefined): FirmwareDifference[] {
  const devices = masterdata?.devices?.length
    ? masterdata.devices
    : ccu?.devices.map((device) => ({
      name: device.name,
      address: device.address,
      type: device.type,
      firmware: device.firmware
    })) ?? [];

  const byType = new Map<string, Array<{ name?: string; firmware?: string }>>();

  for (const device of devices) {
    if (!device.type || !device.firmware) continue;
    const current = byType.get(device.type) ?? [];
    current.push({ name: device.name ?? device.address, firmware: device.firmware });
    byType.set(device.type, current);
  }

  return [...byType.entries()]
    .map(([type, typeDevices]) => ({
      type,
      versions: [...new Set(typeDevices.map((device) => device.firmware).filter(Boolean) as string[])].sort(),
      devices: typeDevices.slice(0, 6).map((device) => `${device.name ?? "Unbenannt"} (${device.firmware})`)
    }))
    .filter((entry) => entry.versions.length > 1)
    .slice(0, 8);
}

function parseAvailableFirmwareUpdates(collector: CollectorPayload | undefined, masterdata: CcuMasterdataPayload | undefined, ccu: CcuSnapshot | undefined): AvailableFirmwareUpdate[] {
  const namesByAddress = new Map<string, string>();
  for (const device of masterdata?.devices ?? ccu?.devices ?? []) {
    if (device.address && device.name) namesByAddress.set(device.address.toUpperCase(), device.name);
  }

  return (collector?.deviceFirmware ?? []).flatMap((line) => {
    if (!line.startsWith("DEVICE_FIRMWARE|")) return [];
    const values = Object.fromEntries(line.split("|").slice(1).map((part) => {
      const separator = part.indexOf("=");
      return separator > 0 ? [part.slice(0, separator), part.slice(separator + 1)] : [part, ""];
    }));
    const address = values.address?.trim();
    const type = values.type?.trim();
    const installed = values.installed?.trim();
    const available = values.available?.trim();
    const state = values.state?.trim();
    const unavailableValues = new Set(["", "-", "0.0", "0.0.0"]);

    if (!address || !type || unavailableValues.has(installed) || unavailableValues.has(available)) return [];
    if (compareFirmwareVersions(available, installed) <= 0 && !/NEW_FIRMWARE_AVAILABLE|READY_FOR_UPDATE|DO_UPDATE_PENDING/i.test(state ?? "")) return [];

    return [{
      name: namesByAddress.get(address.toUpperCase()) ?? address,
      address,
      type,
      installed,
      available,
      state: unavailableValues.has(state) ? undefined : state
    }];
  }).sort((left, right) => left.name.localeCompare(right.name, "de"));
}

function compareFirmwareVersions(left: string, right: string): number {
  const leftParts = left.split(".").map((part) => Number(part.replace(/\D.*$/, "")));
  const rightParts = right.split(".").map((part) => Number(part.replace(/\D.*$/, "")));
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function isReachabilityEvidence(evidence: Evidence): boolean {
  const detail = evidence.detail
    .toLowerCase()
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "");
  return /unreach|nicht erreichbar|kommunikation|communication|geratekommunikation gestort/.test(detail);
}

function isCriticalServiceEvidence(evidence: Evidence): boolean {
  return /\b(?:ERROR_)?OVERHEAT\b|\bSABOTAGE\b|\b(?:SMOKE|WATER|LEAK)(?:_[A-Z0-9]+)?\b/i.test(evidence.detail);
}

function isGatewayDevice(device: Pick<CcuDevice, "name" | "type">): boolean {
  return /^(?:HmIP-(?:HAP|WLAN-HAP|DRAP)|HmIPW-DRAP|HM-(?:LGW|CFG-LAN)|HMLGW)/i.test(device.type ?? "")
    || /(?:funk|lan)[ -]?gateway|access[ -]?point/i.test(device.name);
}

function hasServiceOverheat(evidence: Evidence): boolean {
  return /\b(?:ERROR_)?OVERHEAT\b/i.test(evidence.detail);
}

function isHmIpType(type?: string): boolean {
  return /^HmIP-/i.test(type ?? "");
}

function isLikelyHmIpSerial(serial?: string): boolean {
  return Boolean(serial && (serial.length === 14 || serial === "HmIP-RF"));
}

function isHmIpSnifferDevice(device: SnifferDeviceSummary): boolean {
  return isHmIpType(device.type) || isLikelyHmIpSerial(device.serial);
}

function isHmIpRouterCandidateType(type?: string): boolean {
  if (!type) return false;
  return /^HmIP-(HAP|WLAN-HAP|DRAP|PSM|PSM-2|FSM|FSM16|BSM|PCBS|DRSI|DRDI|DRBLI|FAL|MIOB)/i.test(type);
}

function snifferDeviceLabel(device: SnifferDeviceSummary): string {
  const parts = [device.name || device.address];
  if (device.type) parts.push(device.type);
  if (device.avgRssi !== undefined) parts.push(`Ø ${device.avgRssi} dBm`);
  parts.push(`${device.telegrams} Telegramm${device.telegrams === 1 ? "" : "e"}`);
  return parts.join(" · ");
}

function snifferSignalStatus(devices: SnifferDeviceSummary[]): AnalysisCheck["status"] {
  if (!devices.length) return "unavailable";
  if (devices.some((device) => (device.avgRssi ?? 0) <= -95)) return "warning";
  if (devices.some((device) => (device.avgRssi ?? 0) <= -85)) return "improvement";
  return "ok";
}

function weakSnifferDevices(devices: SnifferDeviceSummary[], limit = -85): SnifferDeviceSummary[] {
  return devices
    .filter((device) => device.avgRssi !== undefined && device.avgRssi <= limit)
    .sort((left, right) => (left.avgRssi ?? 0) - (right.avgRssi ?? 0));
}

export function createAnalysis(
  config: AnalyzeRequest,
  collector?: CollectorPayload,
  ccu?: CcuSnapshot,
  masterdata?: CcuMasterdataPayload,
  release?: ReleaseCheck,
  sniffer?: SnifferSnapshot,
  networkHostnames: Record<string, string> = {},
  centralRelease?: CentralReleaseCheck,
  addonReleases?: AddonReleaseCheck[]
): AnalysisCheck[] {
  const hasCcuCredentials = Boolean(config.ccuHost && config.ccuUser && (config.ccuPassword || config.hasCcuPassword));
  const hasCcuData = Boolean(ccu?.reachable);
  const hasSsh = Boolean((config.sshHost || config.ccuHost || collector?.host) && (config.sshUser || collector));
  const hasSniffer = config.snifferEnabled !== false && Boolean(config.snifferPort);
  const hasNotifications = Boolean(config.notificationSettings?.telegram?.enabled || config.notificationSettings?.email?.enabled || config.telegramEnabled);
  const ccuHostLooksPublic = Boolean(config.ccuHost && !isLocalOrPrivateHost(config.ccuHost));
  const collectorAgeMinutes = collector?.collectedAt
    ? Math.max(0, Math.round((Date.now() - Date.parse(collector.collectedAt)) / 60000))
    : undefined;
  const collectorIsFresh = collectorAgeMinutes !== undefined && Number.isFinite(collectorAgeMinutes) && collectorAgeMinutes <= 3;
  const currentCollector = collectorIsFresh ? collector : undefined;
  const externalAccesses = parseExternalAccesses(currentCollector, config.ccuHost, networkHostnames);
  const publicExternalAccesses = externalAccesses.filter((access) => access.isPublic);
  const busyExternalAccesses = externalAccesses.filter((access) => access.count >= 8);
  const masterdataDeviceCount = masterdata?.deviceCount ?? masterdata?.devices?.length ?? 0;
  const inventoryDevices = masterdata?.devices?.length ? masterdata.devices : ccu?.devices ?? [];
  const hmipDevices = inventoryDevices.filter((device) => isHmIpType(device.type));
  const hmipRouterCandidates = hmipDevices.filter((device) => isHmIpRouterCandidateType(device.type));
  const routingTopology = buildRoutingTopology(
    masterdata,
    [
      ...(currentCollector?.hmipRoutingConfig ?? []),
      ...(currentCollector?.hmipRoutingLogs ?? []),
      ...(currentCollector?.hmipLogs ?? [])
    ],
    currentCollector?.host,
    currentCollector?.collectedAt,
    sniffer?.devices ?? [],
    ccu?.devices ?? [],
    parseRadioGateways(currentCollector?.radioGateways ?? [])
  );
  const snifferDevicesWithRssi = (sniffer?.devices ?? []).filter((device) => device.avgRssi !== undefined);
  const reliableSnifferDevicesWithRssi = snifferDevicesWithRssi.filter((device) => device.telegrams >= 3);
  const provisionalSnifferDevicesWithRssi = snifferDevicesWithRssi.filter((device) => device.telegrams < 3);
  const weakSignalDevices = weakSnifferDevices(reliableSnifferDevicesWithRssi);
  const hmipSnifferDevicesWithRssi = snifferDevicesWithRssi.filter(isHmIpSnifferDevice);
  const weakHmipSnifferDevices = weakSnifferDevices(hmipSnifferDevicesWithRssi);
  const topologyRadioNodes = routingTopology.nodes.filter((node) => node.role !== "central" && node.role !== "gateway");
  const topologyMeasuredNodes = topologyRadioNodes.filter((node) => node.ccuRssi !== undefined || node.snifferRssi !== undefined);
  const weakTopologyNodes = topologyMeasuredNodes.filter((node) => (
    [node.ccuRssi, node.snifferRssi].some((value) => value !== undefined && value <= -85)
  ));
  const firmwareDifferences = findFirmwareDifferences(masterdata, ccu);
  const availableFirmwareUpdates = parseAvailableFirmwareUpdates(currentCollector, masterdata, ccu);
  const lowBatteryDevices = ccu?.devices.filter((device) => device.lowBattery) ?? [];
  const unreachableDevices = ccu?.devices.filter((device) => device.unreachable) ?? [];
  const unreachableServiceMessages = ccu?.serviceMessages.filter(isReachabilityEvidence) ?? [];
  const dedicatedServiceMessages = ccu?.serviceMessages.filter((message) => (
    isBatteryEvidence(message) || isReachabilityEvidence(message) || isConfigPendingEvidence(message)
  )) ?? [];
  const generalServiceMessages = ccu?.serviceMessages.filter((message) => !dedicatedServiceMessages.includes(message)) ?? [];
  const criticalServiceMessages = generalServiceMessages.filter(isCriticalServiceEvidence);
  const overheatServiceMessages = criticalServiceMessages.filter(hasServiceOverheat);
  const knownGatewayNames = new Set(
    routingTopology.nodes
      .filter((node) => node.role === "gateway")
      .flatMap((node) => [node.name, node.serial, node.address])
      .filter((value): value is string => Boolean(value))
      .map((value) => value.toLowerCase())
  );
  const unreachableGatewayDevices = unreachableDevices.filter(isGatewayDevice);
  const unreachableGatewayMessages = unreachableServiceMessages.filter((message) => {
    const detail = message.detail.toLowerCase();
    return [...knownGatewayNames].some((identifier) => detail.includes(identifier));
  });
  const unreachableGatewayCount = Math.max(unreachableGatewayDevices.length, unreachableGatewayMessages.length);
  const unreachableEvidence = unreachableDevices.length > 0
    ? evidenceFromDevices(ccu?.devices ?? [], (device) => device.unreachable)
    : unreachableServiceMessages.slice(0, 8);
  const unreachableCount = unreachableDevices.length || unreachableServiceMessages.length;
  const configPendingDevices = ccu?.devices.filter((device) => device.configPending) ?? [];
  const dutyStatus = dutyCycleStatus(ccu?.dutyCycle);
  const logAnalysis = analyzeLogLines(currentCollector?.logs);
  const hasCcuSystemData = Boolean(masterdata?.system || masterdata?.backups);
  const systemSourceHost = collectorRecordValue(masterdata?.system, "host") ?? collector?.host ?? "unbekanntem Host";
  const systemTemperature = collectorRecordValue(masterdata?.system, "temperatureRaw") ?? collectorRecordValue(collector?.system, "temperatureRaw");
  const systemBackupCount = Number(collectorRecordValue(masterdata?.backups, "count") ?? collectorRecordValue(collector?.backups, "count") ?? "0");
  const systemMissingTemperature = Boolean((hasCcuSystemData || collector) && !systemTemperature);
  const systemMissingBackups = Boolean((hasCcuSystemData || collector) && systemBackupCount === 0);
  const collectorScriptVersion = collectorRecordValue(collector?.system, "collectorScriptVersion");
  const collectorInterval = collectorRecordValue(collector?.system, "collectorInterval");

  const checks: AnalysisCheck[] = [
    {
      id: "ccu-connection",
      title: "Verbindung zur Zentrale",
      category: "Grundlage",
      status: hasCcuData ? "ok" : hasCcuCredentials ? ccu?.webUiReachable ? "warning" : "critical" : "unavailable",
      summary: hasCcuData
        ? `${ccu?.counters.devices ?? 0} Geräte wurden über die CCU gelesen.`
        : hasCcuCredentials
          ? ccuConnectionSummary(ccu)
          : "CCU-Zugang wurde noch nicht eingerichtet.",
      recommendation: hasCcuData
        ? "Die wichtigste Datenquelle funktioniert. Geräte, Servicemeldungen und viele Zustände können bewertet werden."
        : hasCcuCredentials
          ? ccuConnectionRecommendation(ccu)
          : "Im Setup Host, Benutzer, Passwort und XML-API-Token der CCU/RaspberryMatic eintragen.",
      access: ["ccu"],
      evidence: hasCcuData
        ? [{ source: "CCU XML-API", detail: `${ccu?.counters.devices ?? 0} Geräte, ${ccu?.counters.serviceMessages ?? 0} Servicemeldungen gelesen.`, timestamp: ccu?.collectedAt }]
        : hasCcuCredentials
          ? [
              ...ccuDiagnosticEvidence(ccu),
              ...(ccu?.error ? [{ source: "Technischer Fehler", detail: ccu.error, timestamp: ccu.collectedAt }] : [])
            ]
          : [],
      details: [
        "Die Prüfung läuft vom Gerät aus, auf dem der Homematic Analyzer installiert ist – nicht von deinem PC oder Smartphone.",
        "Deshalb kann die WebUI in deinem Browser funktionieren, während ein Proxmox-LXC, Raspberry oder Docker-Host die CCU wegen Netzwerk, DNS oder Firewall nicht erreicht.",
        "Die XML-API ist die zentrale Quelle für Geräte, Servicemeldungen und Live-Zustände.",
        "Ohne diese Quelle bewertet der Analyzer keine Homematic-Probleme."
      ]
    },
    {
      id: "remote-exposure",
      title: "Zugriff von außen",
      category: "Sicherheit",
      status: ccuHostLooksPublic ? "critical" : config.ccuHost ? "ok" : "unavailable",
      summary: ccuHostLooksPublic
        ? "Der eingetragene CCU-Host sieht wie eine öffentliche Adresse oder Domain aus."
        : config.ccuHost
          ? "Der eingetragene CCU-Host sieht nach lokalem Netzwerk aus."
          : "Ohne CCU-Host kann kein Hinweis auf externe Erreichbarkeit geprüft werden.",
      recommendation: ccuHostLooksPublic
        ? "Keine Portweiterleitung zur CCU verwenden. Nutze stattdessen VPN, z. B. WireGuard, Tailscale oder den VPN-Zugang deines Routers."
        : config.ccuHost
          ? "Gut: Für die Analyse lokale IPs oder VPN-Adressen verwenden, nicht die CCU direkt ins Internet stellen."
          : "CCU-Host eintragen. Wenn du von außen zugreifen möchtest: VPN statt Portforwarding nutzen.",
      access: ["ccu"],
      evidence: config.ccuHost
        ? [{ source: "Setup", detail: `Eingetragener CCU-Host: ${normalizeHostForSecurity(config.ccuHost)}.` }]
        : [],
      details: [
        "Portforwarding kann die CCU/WebUI direkt aus dem Internet erreichbar machen.",
        "Der Analyzer kann Router-Regeln nicht sicher auslesen, erkennt aber verdächtige öffentliche Hosts.",
        "Empfehlung: VPN verwenden und die CCU nur im lokalen Netz oder über VPN erreichbar machen."
      ]
    },
    {
      id: "xml-api",
      title: "XML-API Add-on",
      category: "Grundlage",
      status: hasCcuData ? "ok" : hasCcuCredentials && ccu?.xmlApiInstalled === false ? "critical" : hasCcuCredentials ? "warning" : "unavailable",
      summary: hasCcuData
        ? "XML-API ist installiert und liefert Daten."
        : hasCcuCredentials && ccu?.xmlApiInstalled === false
          ? "XML-API wurde auf der Zentrale nicht gefunden."
          : hasCcuCredentials && ccu?.webUiReachable
            ? "Die CCU antwortet, aber die XML-API-Geräteliste konnte nicht verwendet werden."
          : hasCcuCredentials
            ? "Die XML-API konnte nicht geprüft werden, weil bereits der Netzwerkweg vom Analyzer zur CCU scheitert."
            : "XML-API wird geprüft, sobald CCU-Zugangsdaten eingetragen sind.",
      recommendation: hasCcuData
        ? "Kein Handlungsbedarf."
        : hasCcuCredentials && ccu?.xmlApiInstalled === false
          ? "Installiere das XML-API Add-on über die WebUI: Systemsteuerung → Zusatzsoftware → Add-on hochladen/installieren → CCU neu starten."
          : hasCcuCredentials
            ? ccuConnectionRecommendation(ccu)
            : "CCU-Zugangsdaten eintragen und Analyse starten.",
      access: ["ccu"],
      evidence: hasCcuData
        ? [{ source: "CCU XML-API", detail: "/addons/xmlapi/statelist.cgi hat Daten geliefert.", timestamp: ccu?.collectedAt }]
        : hasCcuCredentials
          ? ccuDiagnosticEvidence(ccu).map((item) => ({ ...item, url: xmlApiInstallUrl }))
          : [],
      details: [
        "WebUI erreichbar und XML-API nutzbar sind zwei getrennte Prüfungen.",
        "Ein erfolgreicher Browserzugriff bestätigt nicht automatisch, dass der Analyzer-Server denselben Netzwerkzugriff hat.",
        "Download: https://github.com/homematic-community/XML-API/releases",
        "Installation: WebUI öffnen, Systemsteuerung → Zusatzsoftware, Add-on-Datei hochladen und installieren.",
        "Nach der Installation die Zentrale neu starten und die Analyse erneut ausführen."
      ]
    },
    {
      id: "ccu-masterdata",
      title: "CCU-Daten vorbereitet",
      category: "Grundlage",
      status: masterdataDeviceCount > 0 || hasCcuData ? "ok" : "unavailable",
      summary: masterdataDeviceCount > 0
        ? `${masterdataDeviceCount} Geräte wurden vom CCU Add-on gemeldet.`
        : hasCcuData
          ? "Live-Gerätedaten wurden gelesen; das CCU Add-on ist optional, aber für Zusatzdaten empfohlen."
          : "Das CCU Add-on wurde noch nicht empfangen.",
      recommendation: masterdataDeviceCount > 0
        ? "Gut: Gerätenamen und CCU-Systemwerte stehen unabhängig von Live-Abfragen bereit."
        : hasCcuData
          ? "Kein akuter Handlungsbedarf. Das Add-on ergänzt stabile Stammdaten und Systemwerte."
          : "CCU Add-on aus der App herunterladen und unter Zusatzsoftware installieren.",
      access: ["ccu"],
      evidence: masterdataDeviceCount > 0
        ? [{ source: "CCU Add-on", detail: `${masterdataDeviceCount} Geräte gemeldet.`, timestamp: masterdata?.collectedAt ?? now() }]
        : hasCcuData
          ? [{ source: "CCU XML-API", detail: `${ccu?.counters.devices ?? 0} Geräte wurden live gelesen.`, timestamp: ccu?.collectedAt }]
        : [],
      details: [
        "Stammdaten ändern sich selten und müssen nicht bei jeder Analyse live zusammengesucht werden.",
        "Live-Zustände wie Batterie, Erreichbarkeit und Duty Cycle holt der Analyzer weiter bei Bedarf direkt."
      ]
    },
    {
      id: "alarm-messages",
      title: "Alarmmeldungen",
      category: "Sicherheit",
      status: hasCcuData ? statusForCount(ccu?.counters.alarmMessages ?? 0) : "unavailable",
      summary: hasCcuData
        ? ccu?.counters.alarmMessages
          ? `${ccu.counters.alarmMessages} Alarmmeldungen wurden gefunden.`
          : "Keine Alarmmeldungen gefunden."
        : "Alarmmeldungen können ohne CCU-Daten nicht geprüft werden.",
      recommendation: hasCcuData
        ? ccu?.counters.alarmMessages
          ? "Alarmmeldungen zuerst prüfen und erst danach normale Servicemeldungen abarbeiten."
          : "Kein Handlungsbedarf."
        : "CCU-Zugang und XML-API prüfen.",
      access: ["ccu"],
      evidence: ccu?.alarmMessages.slice(0, 8) ?? [],
      details: [
        "Alarmmeldungen werden getrennt von normalen Servicemeldungen bewertet.",
        "Nur echte Alarmmeldungen der Zentrale werden als kritisch markiert.",
        "Wenn die XML-API keine Alarmmeldungen liefert, behauptet der Analyzer hier keinen Alarm."
      ]
    },
    {
      id: "service-messages",
      title: "Servicemeldungen",
      category: "Geräte",
      status: hasCcuData ? (criticalServiceMessages.length > 0 ? "critical" : generalServiceMessages.length ? "warning" : "ok") : "unavailable",
      summary: hasCcuData
        ? criticalServiceMessages.length
          ? `${criticalServiceMessages.length} kritische Servicemeldung${criticalServiceMessages.length === 1 ? "" : "en"} wurde${criticalServiceMessages.length === 1 ? "" : "n"} gefunden: ${criticalServiceMessages.slice(0, 3).map((message) => message.detail).join(", ")}.`
          : generalServiceMessages.length
          ? `${generalServiceMessages.length} weitere Servicemeldung${generalServiceMessages.length === 1 ? "" : "en"} wurde${generalServiceMessages.length === 1 ? "" : "n"} gefunden.`
          : "Keine Servicemeldungen gefunden."
        : "Servicemeldungen können ohne CCU-Daten nicht geprüft werden.",
      recommendation: hasCcuData
        ? overheatServiceMessages.length
          ? "Überhitzung zeitnah prüfen: Gerät abkühlen lassen, Stromversorgung und Einbauort kontrollieren. Bei wiederholter Meldung Herstellerhinweise beachten."
          : criticalServiceMessages.length
          ? "Sicherheits- oder Manipulationsmeldung zeitnah prüfen. Prüfe Gerät, Umgebung und Herstellerhinweise; bei Rauch-, Wasser- oder Sabotagehinweisen sofort den realen Zustand vor Ort kontrollieren."
          : generalServiceMessages.length
          ? "Prüfe die Meldungen in Ruhe. Kommunikationsstörungen werden als Hinweis bewertet, Überhitzung dagegen kritisch."
          : "Kein Handlungsbedarf."
        : "CCU-Zugang und XML-API prüfen.",
      access: ["ccu"],
      evidence: generalServiceMessages.slice(0, 8),
      details: [
        "Servicemeldungen sind direkte Belege der Zentrale, aber nicht automatisch kritisch.",
        "Batterie, Erreichbarkeit und ausstehende Konfiguration werden ausschließlich in ihren eigenen Prüfpunkten angezeigt, damit keine Meldung doppelt erscheint.",
        "ERROR_OVERHEAT sowie eindeutige Sabotage-, Rauch- und Wassermeldungen werden als kritisch bewertet; Kommunikationsstörungen bleiben zunächst Hinweise."
      ]
    },
    {
      id: "duty-cycle",
      title: "Duty Cycle",
      category: "Funk",
      status: hasCcuData ? dutyStatus : "unavailable",
      summary: hasCcuData
        ? ccu?.dutyCycle === undefined
          ? "Es wurde kein belegter Duty-Cycle-Wert in den CCU-Daten gefunden."
          : `Die CCU meldet einen belegten Duty-Cycle-Wert von ${dutyCycleText(ccu.dutyCycle)}.`
        : "Duty Cycle kann ohne CCU-Daten nicht belegt werden.",
      recommendation: hasCcuData
        ? ccu?.dutyCycle === undefined
          ? "Kein Fehler wird behauptet. Der Analyzer zeigt Duty Cycle erst, wenn ein echter Wert oder eine passende Servicemeldung vorliegt."
          : ccu.dutyCycle >= 90
            ? hasSniffer
              ? "Kritisch: CCU-Wert ernst nehmen und im DC-Analyzer die gemessene Funkzeit nach Geräten aufteilen. Zusätzlich Kommunikationsstörungen, ausstehende Konfigurationen und externe Abfragen prüfen."
              : "Kritisch: Die CCU meldet nur den Gesamtwert, keinen Geräte-Verursacher. Prüfe zuerst Kommunikationsstörungen, ausstehende Konfigurationen, Servicemeldungen und stark abfragende externe Systeme. Für eine echte Geräte-Aufteilung ist der DC-Analyzer mit Sniffer nötig."
            : ccu.dutyCycle >= 70
              ? hasSniffer
                ? "Beobachten: Im DC-Analyzer prüfen, welche Geräte am Sniffer-Standort den größten Anteil an der gemessenen Funkzeit haben. Ohne längeren Verlauf nicht vorschnell Geräte ändern."
                : "Beobachten: Ohne Sniffer ist der Verursacher nicht belegbar. Prüfe als Nächstes Erreichbarkeit, Konfiguration ausstehend, Servicemeldungen, Signalqualität und externe Zugriffe."
              : ccu.dutyCycle >= 50
                ? hasSniffer
                  ? "Erhöht: Den CCU-Wert beobachten und im DC-Analyzer zusätzlich prüfen, welche Geräte beim Sniffer den größten Anteil an der gemessenen Funkzeit haben."
                  : "Erhöht: Den CCU-Wert beobachten. Eine Geräte-Aufteilung ist ohne Sniffer nicht belegbar; prüfe stattdessen Kommunikationsstörungen, ausstehende Konfigurationen und externe Zugriffe."
                : "Kein akuter Handlungsbedarf."
        : "CCU-Zugang einrichten, damit der echte Duty-Cycle-Wert gelesen werden kann.",
      access: ["ccu"],
      evidence: hasCcuData && ccu?.dutyCycle !== undefined
        ? [{ source: "CCU XML-API Duty Cycle", detail: `Zentrale meldet Duty Cycle: ${dutyCycleText(ccu.dutyCycle)}.`, timestamp: ccu.collectedAt }]
        : [],
      details: [
        "Quelle dieses Prüfpunkts ist der von der CCU/XML-API gemeldete Duty-Cycle-Wert der Zentrale.",
        "Die CCU liefert hier nur den Gesamtwert der Funk-Schnittstelle. Sie liefert keine belegbare Aufteilung, welches Gerät wie viel Duty Cycle verursacht.",
        "Nächste Schritte ohne Sniffer: Erreichbarkeit, Konfiguration ausstehend, Servicemeldungen, Signalqualität und externe Zugriffe prüfen.",
        "Nächster Schritt mit Sniffer: DC-Analyzer öffnen und die gemessene Funkzeit der letzten 60 Minuten nach Geräten sortieren.",
        "Der AskSin-Sniffer misst zusätzlich Funktelegramme am Standort des Sniffers. Das ist eine zweite Quelle und keine 1:1-Aufteilung des CCU-Werts.",
        "Schwellwerte: ab 50% Optimierung, ab 70% Hinweis, ab 90% kritisch.",
        "Ein Problem wird nur markiert, wenn ein echter Wert oder eine aktive Servicemeldung vorliegt."
      ]
    },
    {
      id: "batteries",
      title: "Batterien",
      category: "Geräte",
      status: hasCcuData ? (lowBatteryDevices.length > 0 ? "warning" : "ok") : "unavailable",
      summary: hasCcuData
        ? lowBatteryDevices.length
          ? `${lowBatteryDevices.length} Geräte melden einen niedrigen Batteriestand: ${deviceNames(ccu?.devices ?? [], (device) => device.lowBattery)}.`
          : "Keine niedrigen Batteriestände gefunden."
        : "Batteriezustände sind ohne CCU-Daten nicht verfügbar.",
      recommendation: hasCcuData
        ? lowBatteryDevices.length
          ? "Batterien der genannten Geräte zeitnah tauschen und danach prüfen, ob die Meldung verschwindet."
          : "Kein Handlungsbedarf."
        : "CCU-Zugang einrichten, um niedrige Batterien nachweisbar zu erkennen.",
      access: ["ccu"],
      evidence: evidenceFromDevices(ccu?.devices ?? [], (device) => device.lowBattery),
      details: [
        "Ausgewertet werden LOWBAT/LOW_BAT/BATTERY_LOW-Datenpunkte und passende Servicemeldungen.",
        "Ohne belegten Status bleibt der Punkt OK oder nicht möglich."
      ]
    },
    {
      id: "reachability",
      title: "Erreichbarkeit",
      category: "Geräte",
      status: hasCcuData ? (unreachableGatewayCount > 0 ? "critical" : unreachableCount > 0 ? "warning" : "ok") : "unavailable",
      summary: hasCcuData
        ? unreachableGatewayCount > 0
          ? `${unreachableGatewayCount} Funk-Gateway${unreachableGatewayCount === 1 ? "" : "s"} nicht erreichbar. Die Funkabdeckung kann dadurch deutlich eingeschränkt sein.`
        : unreachableDevices.length
          ? `${unreachableDevices.length} Geräte sind auffällig: ${deviceNames(ccu?.devices ?? [], (device) => device.unreachable)}.`
          : unreachableServiceMessages.length
            ? `${unreachableServiceMessages.length} Erreichbarkeits-Servicemeldungen wurden gefunden.`
          : "Keine nicht erreichbaren Geräte gefunden."
        : "Erreichbarkeit kann ohne CCU-Daten nicht geprüft werden.",
      recommendation: hasCcuData
        ? unreachableGatewayCount > 0
          ? "Kritisch: Stromversorgung, Netzwerkverbindung und Status-LED des Gateways sofort prüfen. Bis zur Wiederherstellung können zugeordnete Geräte schlechter oder gar nicht erreichbar sein."
        : unreachableCount
          ? "Betroffene Geräte auf Strom/Batterie, Entfernung und Funkhindernisse prüfen. Kritisch wird es erst bei Alarmmeldung oder wiederholter Störung."
          : "Kein Handlungsbedarf."
        : "CCU-Zugang einrichten, um nicht erreichbare Geräte nachweisbar zu erkennen.",
      access: ["ccu"],
      evidence: unreachableGatewayCount > 0
        ? [
            ...evidenceFromDevices(unreachableGatewayDevices, () => true),
            ...unreachableGatewayMessages
          ].slice(0, 8)
        : unreachableEvidence,
      details: [
        "Funk-Gateways und Access Points sind Infrastruktur. Ein belegter Ausfall wird deshalb kritisch bewertet.",
        "Als Hinweis zählen aktive Servicemeldungen der Zentrale und zuordenbare Gerätebelege.",
        "Normale Servicemeldungen sind nicht automatisch kritisch.",
        "Historische UNREACH-/STICKY_UNREACH-Rohkanäle werden nicht mehr allein als aktueller Fehler gezählt."
      ]
    },
    {
      id: "config-pending",
      title: "Konfiguration ausstehend",
      category: "Geräte",
      status: hasCcuData ? (configPendingDevices.length > 0 ? "warning" : "ok") : "unavailable",
      summary: hasCcuData
        ? configPendingDevices.length
          ? `${configPendingDevices.length} Geräte haben ausstehende Konfiguration: ${deviceNames(ccu?.devices ?? [], (device) => device.configPending)}.`
          : "Keine ausstehende Gerätekonfiguration gefunden."
        : "Ausstehende Konfiguration kann ohne CCU-Daten nicht geprüft werden.",
      recommendation: hasCcuData
        ? configPendingDevices.length
          ? "Geräte gemäß Herstellerhinweis aufwecken oder bedienen, damit die Konfiguration übertragen wird."
          : "Kein Handlungsbedarf."
        : "CCU-Zugang einrichten, um ausstehende Konfiguration nachweisbar zu erkennen.",
      access: ["ccu"],
      evidence: evidenceFromDevices(ccu?.devices ?? [], (device) => device.configPending),
      details: [
        "Ausstehende Konfiguration kann Geräteverhalten verzögern oder Meldungen offen halten.",
        "Die App markiert diesen Punkt nur bei passendem Datenpunkt, Gerätelisteneintrag oder Servicemeldung."
      ]
    },
    {
      id: "signal-strength",
      title: "Signalqualität",
      category: "Funk",
      status: topologyMeasuredNodes.length > 0
        ? weakTopologyNodes.some((device) => (
          [device.ccuRssi, device.snifferRssi].some((value) => value !== undefined && value <= -95)
        ))
          ? "warning"
          : weakTopologyNodes.length > 0 ? "improvement" : "ok"
        : snifferDevicesWithRssi.length > 0 ? "improvement" : "unavailable",
      summary: topologyMeasuredNodes.length > 0
        ? weakTopologyNodes.length > 0
          ? `${topologyMeasuredNodes.length} Geräte mit RSSI bewertet. Auffällig: ${weakTopologyNodes.slice(0, 5).map((device) => `${device.name} (Zentrale ${device.ccuRssi ?? "–"} / Sniffer ${device.snifferRssi ?? "–"} dBm)`).join(", ")}.`
          : `${topologyMeasuredNodes.length} Geräte mit RSSI bewertet. Keine auffällig schwachen Werte von Zentrale oder Sniffer.`
        : snifferDevicesWithRssi.length > 0
          ? `${snifferDevicesWithRssi.length} Snifferwerte vorhanden, aber noch nicht sicher CCU-Geräten zugeordnet. Zentralenwert daher noch nicht verfügbar; für eine belastbare Snifferbewertung sind mindestens 3 Telegramme nötig.`
          : "Noch keine belegbaren RSSI-Werte von Zentrale oder Sniffer vorhanden.",
      recommendation: topologyMeasuredNodes.length > 0
        ? weakTopologyNodes.length > 0
          ? "Beide Messpositionen vergleichen. Ist nur der Sniffer schwach, kann dessen Standort ungünstig sein. Ist auch die Zentrale schwach, Gerät, Entfernung und passenden Router beziehungsweise Gateway prüfen."
          : "Kein unmittelbarer Handlungsbedarf. Zentrale und Sniffer messen an unterschiedlichen Orten und dürfen voneinander abweichen."
        : snifferDevicesWithRssi.length > 0
          ? "Sniffer 30 bis 60 Minuten weiterlaufen lassen und CCU-Stammdaten beziehungsweise AskSinAnalyzerDevList aktualisieren, damit Sniffer- und Zentralenwert demselben Gerät zugeordnet werden können."
          : "CCU/XML-API für Zentralen-RSSI prüfen. Optional einen Sniffer ergänzen, wenn eine zweite Messposition und Funklastdaten benötigt werden.",
      access: hasSniffer ? ["ccu", "sniffer"] : ["ccu"],
      evidence: topologyMeasuredNodes.length > 0
        ? [
          {
            source: "RSSI-Vergleich",
            detail: `${topologyMeasuredNodes.length} Geräte bewertet. Zentralenwerte: ${routingTopology.rssiSources.ccu}, Snifferwerte: ${routingTopology.rssiSources.sniffer}.`,
            timestamp: sniffer?.checkedAt ?? ccu?.collectedAt ?? now()
          },
          ...weakTopologyNodes.slice(0, 8).map((device) => ({
            source: "RSSI-Vergleich",
            detail: `${device.name}: Zentrale ${device.ccuRssi ?? "nicht verfügbar"} dBm, Sniffer ${device.snifferRssi ?? "nicht verfügbar"} dBm.`,
            timestamp: sniffer?.checkedAt ?? ccu?.collectedAt
          }))
        ]
        : snifferDevicesWithRssi.length > 0
          ? [{
            source: "Sniffer-RSSI",
            detail: `${snifferDevicesWithRssi.length} Snifferwerte vorhanden; passende Zentralenwerte konnten noch nicht zugeordnet werden.`,
            timestamp: sniffer?.checkedAt
          }]
          : [],
      details: [
        "Der Zentralenwert stammt aus der CCU/XML-API. Der Snifferwert beschreibt den Empfang am Standort des Sniffers.",
        "Snifferwerte werden erst mit mehreren Telegrammen belastbarer; Zentralen- und Snifferwert können wegen verschiedener Standorte deutlich abweichen.",
        "Ohne Messwert bleibt der Punkt bewusst nicht geprüft."
      ]
    },
    {
      id: "routing-topology",
      title: "Funk-Infrastruktur",
      category: "Funk",
      status: routingTopology.metrics.devices > 0
        ? "ok"
        : hasCcuData || masterdataDeviceCount > 0 ? "ok" : "unavailable",
      summary: routingTopology.metrics.devices > 0
        ? `${routingTopology.metrics.gateways} Funk-Gateway${routingTopology.metrics.gateways === 1 ? "" : "s"}, ${routingTopology.metrics.confirmedRouters} bestätigte HmIP-Router und ${routingTopology.metrics.routerCandidates} mögliche netzversorgte Router erkannt.`
        : "Keine Funk-Infrastruktur in den verfügbaren Gerätedaten erkannt.",
      recommendation: routingTopology.metrics.devices > 0
        ? "Die CCU stellt keine belastbare Live-Tabelle der aktiven HmIP-Funkwege bereit. Prüfe schwache Geräte in der Signalqualität und vergleiche bei Bedarf den Sniffer im DC-Analyzer."
        : "CCU-Zugang oder tägliches Stammdaten-Script einrichten.",
      access: ["ccu"],
      evidence: routingTopology.metrics.devices > 0
        ? [
          ...(routingTopology.metrics.confirmedRouters > 0 || routingTopology.metrics.routingEnabled > 0 ? [{
            source: "CCU Router-Konfiguration",
            detail: `${routingTopology.metrics.confirmedRouters} bestätigte Router, ${routingTopology.metrics.routingEnabled} Geräte mit aktivem Routing und ${routingTopology.metrics.multicastRouters} Multicast-Router. Aktive Gerätepfade werden von der CCU nicht als auswertbare Tabelle geliefert.`,
            timestamp: currentCollector?.collectedAt
          }] : []),
          {
            source: masterdataDeviceCount > 0 ? "CCU-Stammdaten" : "CCU XML-API",
            detail: `${routingTopology.metrics.hmipDevices} HmIP-Geräte, ${routingTopology.metrics.bidcosDevices} klassische Homematic-Geräte und ${routingTopology.metrics.gateways} Funk-Gateways erkannt. Mögliche HmIP-Router: ${hmipRouterCandidates.slice(0, 10).map((device) => `${device.name ?? device.address ?? "Unbenannt"} (${device.type})`).join(", ") || "keine sicher erkannt"}.`,
            timestamp: masterdata?.collectedAt ?? ccu?.collectedAt ?? now()
          },
          ...(hmipSnifferDevicesWithRssi.length > 0 ? [{
            source: "Sniffer-RSSI",
            detail: `${hmipSnifferDevicesWithRssi.length} HmIP-Geräte mit RSSI am Sniffer gesehen. Schwelle: ab -85 dBm Optimierung, ab -95 dBm Hinweis.`,
            timestamp: sniffer?.checkedAt
          }] : []),
          ...weakHmipSnifferDevices.slice(0, 8).map((device) => ({
            source: "Sniffer-RSSI",
            detail: snifferDeviceLabel(device),
            timestamp: device.lastSeen
          }))
        ]
        : [],
      details: [
        "Gateways sind zusätzliche Funkempfänger. Nur ausdrücklich konfigurierte HmIP-Geräte werden als Router bezeichnet.",
        "Die CCU liefert keine belastbare Live-Topologie mit dem aktuell verwendeten nächsten Empfänger pro Gerät.",
        "RSSI bewertet die Empfangsqualität, nicht den tatsächlich genutzten Funkweg. Funkzeit-Anteile pro Gerät stehen im DC-Analyzer nur mit Sniffer zur Verfügung."
      ]
    },
    {
      id: "firmware-overview",
      title: "Geräte-Firmware",
      category: "Wartung",
      status: masterdataDeviceCount > 0 || hasCcuData
        ? availableFirmwareUpdates.length > 0 || firmwareDifferences.length > 0
          ? "warning"
          : "ok"
        : "unavailable",
      summary: masterdataDeviceCount > 0 || hasCcuData
        ? availableFirmwareUpdates.length > 0
          ? availableFirmwareUpdates.length === 1
            ? `Für 1 Gerät meldet die CCU eine neuere Firmware.`
            : `Für ${availableFirmwareUpdates.length} Geräte meldet die CCU eine neuere Firmware.`
          : firmwareDifferences.length > 0
          ? `${firmwareDifferences.length} Gerätetypen laufen mit unterschiedlichen Firmwareständen.`
          : "Keine verfügbaren Geräte-Updates oder unterschiedlichen Firmwarestände gefunden."
        : "Firmware kann ohne CCU-Daten oder Stammdaten-Script nicht verglichen werden.",
      recommendation: masterdataDeviceCount > 0 || hasCcuData
        ? availableFirmwareUpdates.length > 0
          ? "Öffne in der CCU-WebUI „Einstellungen → Geräte-Firmware – Übersicht“. Prüfe die Hinweise je Gerät und starte Updates bewusst nacheinander."
          : firmwareDifferences.length > 0
          ? "Prüfe die genannten Gerätetypen in der WebUI. Unterschiedliche Stände sind nicht immer falsch, aber ein guter Wartungshinweis."
          : "Kein Handlungsbedarf."
        : "CCU-Zugang oder tägliches Stammdaten-Script einrichten.",
      access: ["ccu"],
      evidence: [
        ...availableFirmwareUpdates.slice(0, 20).map((update) => ({
          source: "CCU Firmwarestatus",
          detail: `${update.name} (${update.type}): installiert ${update.installed}, verfügbar ${update.available}${update.state ? ` · Status ${update.state}` : ""}.`,
          timestamp: currentCollector?.collectedAt ?? now()
        })),
        ...firmwareDifferences.map((difference) => ({
          source: "Firmware-Vergleich",
          detail: `${difference.type}: Versionen ${difference.versions.join(", ")}; Beispiele: ${difference.devices.join(", ")}.`,
          timestamp: masterdata?.collectedAt ?? ccu?.collectedAt ?? now()
        }))
      ].slice(0, 24),
      details: [
        "Verfügbare Geräte-Firmware stammt aus den offiziellen CCU-Gerätebeschreibungen `AVAILABLE_FIRMWARE` und `FIRMWARE_UPDATE_STATE`.",
        "Zusätzlich vergleicht der Analyzer Geräte gleichen Typs innerhalb deiner Installation.",
        "Die CCU entscheidet, ob eine Firmware für das konkrete Gerät angeboten und aktualisiert werden kann.",
        "Unterschiedliche Versionen sind ein Hinweis, aber nicht automatisch ein Fehler."
      ]
    },
    {
      id: "system-health",
      title: "Raspberry / Zentrale",
      category: "System",
      status: hasCcuSystemData || collector ? "ok" : "unavailable",
      summary: hasCcuSystemData
        ? `CCU-Systemwerte wurden vom CCU Add-on gelesen (${systemSourceHost}).`
        : collector
          ? `Systemwerte stammen vom CCU Add-on Collector (${systemSourceHost}).`
        : hasSsh
          ? "SSH-Zugang ist eingetragen, aber es liegen noch keine Systemwerte vor."
        : "Systemwerte brauchen das CCU Add-on.",
      recommendation: hasCcuSystemData || collector
        ? systemMissingTemperature || systemMissingBackups
          ? "Wenn Temperatur oder Backups fehlen, das CCU Add-on einmal aktualisieren und prüfen, ob Backup-Dateien unter /usr/local/backup, /media oder /mnt liegen."
          : "Behalte Temperatur, freien Speicher und Backup-Anzahl im Blick."
        : hasSsh
          ? "CCU Add-on oder Add-on Collector ausführen, bevor Systemwerte bewertet werden."
        : "CCU Add-on einrichten. Das ist der bevorzugte Weg für CCU3/RaspberryMatic-Systemwerte.",
      access: ["ssh"],
      evidence: hasCcuSystemData
        ? [{ source: "CCU Add-on", detail: `Systemvariablen der Zentrale gelesen. Temperatur: ${systemMissingTemperature ? "nicht verfügbar" : "vorhanden"}. Backups: ${systemBackupCount} gefunden.`, timestamp: masterdata?.collectedAt ?? now() }]
        : collector
          ? [{ source: "CCU Add-on Collector", detail: `Fallback-Daten von ${systemSourceHost}. Temperatur: ${systemMissingTemperature ? "nicht verfügbar" : "vorhanden"}. Backups: ${systemBackupCount} gefunden.${collectorScriptVersion ? ` Collector-Version: ${collectorScriptVersion}.` : " Collector-Version wurde noch nicht mitgeliefert; bitte den aktuellen Installationsbefehl einmal neu ausführen."}${collectorInterval ? ` Intervall: ${collectorInterval}.` : ""}`, timestamp: collector.collectedAt ?? now() }]
        : hasSsh
          ? [{ source: "SSH-Setup", detail: `SSH-Ziel ${config.sshHost ?? config.ccuHost} wurde angegeben.`, timestamp: now() }]
          : [],
      details: [
        "Bevorzugte Quelle ist das CCU Add-on auf der Zentrale.",
        "Der CCU Add-on Collector ist nur Fallback oder Ergänzung für Logs und aktive Verbindungen.",
        "Bewertet werden nur Werte, die von der CCU/RaspberryMatic selbst geliefert wurden."
      ]
    },
    {
      id: "logs",
      title: "Log-Auswertung",
      category: "Belege",
      status: currentCollector?.logs?.length ? logAnalysis.status : "unavailable",
      summary: currentCollector?.logs?.length
        ? logAnalysis.relevantLines.length > 0
          ? `${logAnalysis.relevantLines.length} auffällige Logzeilen wurden gefunden.`
          : "Es liegen Logdaten vor, aber keine belegbaren Fehler-/Warnmuster."
        : collector && !collectorIsFresh
          ? `Der Collector wurde früher erkannt, aber der letzte Snapshot ist ${collectorAgeMinutes ?? "viele"} Minuten alt.`
        : hasSsh
          ? "Loganalyse ist vorbereitet, aber es liegen noch keine Logdaten vor."
          : "Loganalyse ist ohne SSH oder CCU Add-on nicht möglich.",
      recommendation: currentCollector?.logs?.length
        ? logAnalysis.relevantLines.length > 0
          ? "Prüfe die genannten Logzeilen. Nur diese werden als Auffälligkeit gewertet."
          : "Kein Handlungsbedarf aus diesen Logzeilen. Debug/Verbose-Ausgaben sind normale technische Protokolleinträge."
        : collector && !collectorIsFresh
          ? "Das Add-on war bereits eingerichtet. Prüfe es in der CCU-Zusatzsoftware oder installiere es erneut."
        : "CCU Add-on ausführen, damit echte Logbelege in die Analyse einfließen.",
      access: ["ssh"],
      evidence: currentCollector?.logs?.length
        ? (logAnalysis.relevantLines.length > 0 ? logAnalysis.relevantLines : logAnalysis.noisyLines).slice(0, 5).map((line) => ({
          source: logAnalysis.relevantLines.length > 0 ? "Auffällige Logzeile" : "Unauffällige Debug-/Verbose-Logzeile",
          detail: line,
          timestamp: currentCollector.collectedAt ?? now()
        }))
        : collector && !collectorIsFresh
          ? [{
            source: "Collector-Verlauf",
            detail: `Letzter Empfang von ${collector.host ?? "der Zentrale"} vor ${collectorAgeMinutes ?? "vielen"} Minuten.`,
            timestamp: collector.collectedAt
          }]
        : [],
      details: [
        "Die App soll niemals aus Bauchgefühl urteilen: Jeder Fehler bekommt eine Quelle.",
        "Debug- und Verbose-Zeilen werden nicht als Fehler gewertet.",
        "Bekannte Muster wie Kommunikationsstörung, Scriptfehler oder Dienstneustart werden nur bei passenden Logbegriffen markiert."
      ]
    },
    {
      id: "external-access",
      title: "Zugriffe anderer Systeme auf die CCU",
      category: "Anbindungen",
      status: currentCollector
        ? publicExternalAccesses.length > 0
          ? "critical"
          : "ok"
        : "unavailable",
      summary: currentCollector
        ? publicExternalAccesses.length > 0
          ? publicExternalAccesses.length === 1
            ? `Öffentliche Gegenstelle mit CCU-Diensten verbunden: ${externalAccessSummary(publicExternalAccesses[0]!)}.`
            : `${publicExternalAccesses.length} öffentliche Gegenstellen sind aktiv mit CCU-Diensten verbunden: ${publicExternalAccesses.slice(0, 2).map(externalAccessSummary).join("; ")}${publicExternalAccesses.length > 2 ? " …" : ""}.`
          : busyExternalAccesses.length > 0
            ? busyExternalAccesses.length === 1
              ? `Lokale CCU-Verbindungen werden beobachtet: ${externalAccessSummary(busyExternalAccesses[0]!)}. Die Anzahl allein ist kein Fehler.`
              : `${busyExternalAccesses.length} lokale Systeme haben mehrere CCU-Verbindungen: ${busyExternalAccesses.slice(0, 2).map(externalAccessSummary).join("; ")}${busyExternalAccesses.length > 2 ? " …" : ""}. Die Anzahl allein ist kein Fehler.`
            : externalAccesses.length > 0
              ? externalAccesses.length === 1
                ? `Aktiver Zugriff auf CCU-Dienste: ${externalAccessSummary(externalAccesses[0]!)}.`
                : `${externalAccesses.length} lokale Systeme greifen aktuell auf CCU-Dienste zu: ${externalAccesses.slice(0, 2).map(externalAccessSummary).join("; ")}${externalAccesses.length > 2 ? " …" : ""}.`
              : "Keine aktiven Zugriffe anderer Systeme auf typische CCU-Dienste gefunden."
        : hasSsh
          ? "Der Check ist vorbereitet; es liegen aber noch keine Verbindungsdaten vom Collector vor."
          : "Ohne SSH oder Collector können externe Zugriffe nicht belegbar erkannt werden.",
      recommendation: currentCollector
        ? publicExternalAccesses.length > 0
          ? "CCU nicht per Portweiterleitung veröffentlichen. Verbindung sofort prüfen und künftig VPN verwenden."
          : busyExternalAccesses.length > 0
            ? "Kein Handlungsbedarf allein aus der Anzahl. Erst ein belegter Lastanstieg, passende Fehler im Log oder ein öffentlicher Zugriff ergibt einen Warnhinweis."
            : externalAccesses.length > 0
              ? "Ordne die IPs den Systemen zu. Erst wenn viele Verbindungen, Logs oder Lastspitzen zusammenpassen, wird daraus ein echtes Problem."
              : "Kein Handlungsbedarf."
        : collector && !collectorIsFresh
          ? "Add-on-Verbindung erneuern. Veraltete Verbindungsdaten werden bewusst nicht bewertet."
          : "CCU Add-on ausführen, damit aktive CCU-Verbindungen sichtbar werden.",
      access: ["ssh", "external"],
      evidence: externalAccesses.map((access) => {
        const serviceHint = describeKnownService(access.hostname);
        const displayName = externalAccessDisplayName(access);
        const networkType = access.isPublic ? "öffentliche Adresse" : "Gerät im Heimnetz";
        const stateText = access.states.includes("ESTABLISHED")
          ? "mindestens eine Verbindung ist gerade aktiv"
          : access.states.length > 0
            ? `Status: ${access.states.join(", ")}`
            : "Verbindungsstatus nicht eindeutig";

        return {
          source: access.isPublic ? "Öffentliche Gegenstelle" : "Gerät im Heimnetz",
          detail: `${displayName}: ${access.count} Verbindung(en) zu ${access.ports.map((port) => ccuServiceLabels[port] ?? `Port ${port}`).join(", ")} · ${networkType} · ${stateText}.${serviceHint ? ` ${serviceHint}` : access.hostname ? " Der Gerätename wurde per lokaler Namensauflösung ermittelt." : " Ein Gerätename konnte im lokalen Netz nicht aufgelöst werden."}`,
          timestamp: collector?.collectedAt ?? now()
        };
      }).slice(0, 10),
      details: [
        "Die App versucht den Gerätenamen über die lokale Namensauflösung des Analyzer-Systems zu ermitteln. Das funktioniert nur, wenn Router oder DNS-Server einen Namen kennen.",
        "Nur wenn ein aufgelöster Gerätename eindeutig Begriffe wie ioBroker oder Home Assistant enthält, wird dies als vorsichtiger Hinweis genannt.",
        "Er zeigt aktive Gegenstellen zu typischen CCU-Ports wie WebUI, XML-API, BidCos-RPC und HmIP-RPC.",
        "Viele gleichzeitige lokale Verbindungen sind allein kein Fehler und lösen keine Benachrichtigung aus. Erst ein belegter Lastanstieg, passende Fehler im Log oder ein öffentlicher Zugriff ergibt einen Warnhinweis.",
        "Öffentliche Gegenstellen sind kritisch: Die CCU sollte nicht per Portforwarding erreichbar sein."
      ]
    },
    {
      id: "notifications",
      title: "Benachrichtigungen",
      category: "Benachrichtigung",
      status: "ok",
      summary: hasNotifications
        ? "Benachrichtigungen sind für ausgewählte Ereignisse vorbereitet."
        : "Telegram und E-Mail sind optional und noch nicht eingerichtet.",
      recommendation: hasNotifications
        ? "Kein Handlungsbedarf."
        : "Nur einrichten, wenn du aktiv über kritische Ereignisse informiert werden möchtest.",
      access: ["telegram"],
      evidence: hasNotifications
        ? [{ source: "Settings", detail: "Mindestens ein Benachrichtigungskanal ist aktiviert.", timestamp: now() }]
        : [],
      details: [
        "Benachrichtigungen sollten selten und relevant sein.",
        "Jede Meldung enthält den Grund und den Beleg, nicht nur einen Alarmtext."
      ]
    }
  ];

  if (release) {
    checks.push({
      id: "app-release",
      title: "Analyzer Update",
      category: "Wartung",
      status: release.available ? "warning" : release.error ? "improvement" : "ok",
      summary: release.available
        ? `Neue Analyzer-Version verfügbar: ${release.latestVersion}.`
        : release.error
          ? "Release-Check konnte nicht vollständig durchgeführt werden."
          : "Keine neuere Analyzer-Version gefunden.",
      recommendation: release.available
        ? "Repository öffnen, Änderungen prüfen und Update bewusst installieren."
        : release.error
          ? "Internetverbindung oder GitHub-Erreichbarkeit prüfen."
          : "Kein Handlungsbedarf.",
      access: ["ccu"],
      evidence: [{
        source: "GitHub Release-Check",
        detail: release.available
          ? `Installiert: ${release.currentVersion}, neu: ${release.latestVersion}.`
          : release.error ?? `Installiert: ${release.currentVersion}.`,
        timestamp: release.checkedAt,
        url: release.url
      }],
      details: [
        "Dieser Check bezieht sich nur auf den Homematic Analyzer selbst.",
        "Die Zentralensoftware wird separat mit der passenden Quelle für OpenCCU/RaspberryMatic oder die originale CCU3 verglichen."
      ]
    });
  }

  if (centralRelease) {
    const hasInstalledVersion = Boolean(centralRelease.installedVersion);
    const centralVersionDiagnostic = ccu?.diagnostics?.find((diagnostic) => diagnostic.step === "Zentralenversion");
    const centralReleaseName = centralRelease.source === "ccu3" ? "CCU3" : "OpenCCU";
    checks.push({
      id: "central-release",
      title: hasInstalledVersion ? `${centralReleaseName} Update` : "Zentralen-Version",
      category: "Wartung",
      status: centralRelease.available ? "warning" : centralRelease.error ? "improvement" : !hasInstalledVersion ? "unavailable" : "ok",
      summary: centralRelease.available
        ? `Neue ${centralReleaseName}-Version verfügbar: ${centralRelease.latestVersion}.`
        : centralRelease.error
          ? `Der ${centralReleaseName}-Stand konnte gerade nicht geprüft werden.`
          : !hasInstalledVersion
            ? "Die installierte Zentralenversion wurde noch nicht belegbar gelesen. Es wird deshalb kein Update behauptet."
            : `Die Zentrale ist aktuell (${centralRelease.installedVersion}).`,
      recommendation: centralRelease.available
        ? "Release-Hinweise öffnen, Backup erstellen und das Zentralen-Update anschließend bewusst über die CCU-WebUI installieren."
        : centralRelease.error
          ? "Internetverbindung des Analyzer-Systems prüfen. Die App versucht den Online-Check im Hintergrund erneut."
          : !hasInstalledVersion
            ? "Den aktuellen CCU Add-on Collector einmal neu ausführen oder den nächsten Collector-Lauf abwarten. Erst wenn die installierte Version gelesen wurde, vergleicht die App sie mit dem Online-Release."
            : "Kein Handlungsbedarf.",
      access: ["ccu", "ssh"],
      evidence: [
        {
          source: centralRelease.source === "ccu3" ? "Offizieller CCU3-Update-Dienst" : "OpenCCU Release",
          detail: hasInstalledVersion
            ? `Installiert: ${centralRelease.product ? `${centralRelease.product} ` : ""}${centralRelease.installedVersion}. Verfügbar: ${centralRelease.latestVersion ?? "nicht ermittelbar"}.`
            : `Online gefunden: ${centralRelease.latestVersion ?? "nicht ermittelbar"}. Keine Update-Aussage, weil die installierte Version noch fehlt.`,
          timestamp: centralRelease.checkedAt,
          url: centralRelease.url
        },
        ...(!hasInstalledVersion && centralVersionDiagnostic ? [{
          source: "Zentralenversion",
          detail: centralVersionDiagnostic.detail,
          timestamp: ccu?.collectedAt
        }] : [])
      ],
      details: [
        "Die installierte Version wird bevorzugt live aus der CCU-WebUI gelesen; der CCU Add-on Collector liefert zusätzlich `/VERSION` der Zentrale.",
        centralRelease.source === "ccu3"
          ? "Der verfügbare Stand kommt aus dem offiziellen eQ-3-Update-Dienst, den auch die CCU3-WebUI verwendet."
          : "Der verfügbare Stand kommt aus dem offiziellen OpenCCU-Repository.",
        "Nach einem Zentralen-Update erkennt die App den Stand automatisch beim nächsten Hintergrundlauf; der Collector ist nur nötig, wenn die Live-WebUI-Version nicht gelesen werden kann.",
        "Der Analyzer installiert Zentralen-Updates niemals automatisch."
      ]
    });
  }

  if (addonReleases && addonReleases.length > 0) {
    for (const addon of addonReleases) {
      const hasInstalledVersion = Boolean(addon.installedVersion);
      const safeId = addon.name.toLowerCase().replace(/[^a-z0-9]/g, "-");
      checks.push({
        id: `addon-release-${safeId}`,
        title: `${addon.name} Update`,
        category: "Wartung",
        status: addon.available ? "warning" : addon.error ? "improvement" : !hasInstalledVersion ? "unavailable" : "ok",
        summary: addon.available
          ? `Neues ${addon.name}-Update verfügbar: Version ${addon.latestVersion}.`
          : addon.error
            ? `Der Update-Check für ${addon.name} konnte nicht durchgeführt werden.`
            : !hasInstalledVersion
              ? `Die installierte Version von ${addon.name} konnte noch nicht ermittelt werden.`
              : `${addon.name} ist aktuell (${addon.installedVersion}).`,
        recommendation: addon.available
          ? `Release-Hinweise öffnen, Add-on herunterladen und über die CCU-WebUI unter Systemsteuerung → Zusatzsoftware installieren.`
          : addon.error
            ? `Internetverbindung oder GitHub-Erreichbarkeit prüfen.`
            : !hasInstalledVersion
              ? `CCU-Zusatzsoftware prüfen oder den Collector ausführen, um die Versionsnummer zu ermitteln.`
              : "Kein Handlungsbedarf.",
        access: ["ccu"],
        evidence: [{
          source: "GitHub Add-on Release",
          detail: hasInstalledVersion
            ? `Installiert: ${addon.installedVersion}. Verfügbar: ${addon.latestVersion ?? "nicht ermittelbar"}.`
            : `Online gefunden: ${addon.latestVersion ?? "nicht ermittelbar"}. Installierte Version noch unbekannt.`,
          timestamp: addon.checkedAt,
          url: addon.url
        }],
        details: [
          `Prüfung gegen das offizielle GitHub-Repository für ${addon.name}.`,
          "Add-on-Updates werden manuell über die CCU-WebUI unter Systemsteuerung → Zusatzsoftware eingespielt.",
          "Vor Add-on-Updates empfiehlt sich die Erstellung eines CCU-Backups."
        ]
      });
    }
  }

  return config.hmipRoutingEnabled
    ? checks
    : checks.filter((check) => check.id !== "routing-topology");
}
