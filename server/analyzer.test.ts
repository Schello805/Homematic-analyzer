import assert from "node:assert/strict";
import test from "node:test";
import { createAnalysis } from "./analyzer.js";
import type { CcuSnapshot, CollectorPayload, SnifferSnapshot } from "./types.js";

function failedSnapshot(overrides: Partial<CcuSnapshot>): CcuSnapshot {
  return {
    reachable: false,
    xmlApiInstalled: true,
    source: "xml-api",
    collectedAt: "2026-06-12T17:00:00.000Z",
    devices: [],
    serviceMessages: [],
    alarmMessages: [],
    counters: {
      devices: 0,
      lowBattery: 0,
      unreachable: 0,
      configPending: 0,
      serviceMessages: 0,
      alarmMessages: 0
    },
    ...overrides
  };
}

test("bewertet erreichbare WebUI mit gescheiterter XML-API als Hinweis statt Totalausfall", () => {
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret" },
    undefined,
    failedSnapshot({
      webUiReachable: true,
      xmlApiReachable: true,
      authentication: "failed",
      errorCode: "authentication",
      diagnostics: [
        { step: "Netzwerk / WebUI", status: "ok", detail: "HTTP 200" },
        { step: "XML-API Geräteliste", status: "failed", detail: "Token abgelehnt" }
      ]
    })
  );
  const connection = checks.find((check) => check.id === "ccu-connection");

  assert.equal(connection?.status, "warning");
  assert.match(connection?.summary ?? "", /WebUI antwortet/);
  assert.equal(connection?.evidence.length, 2);
});

test("stuft ERROR_OVERHEAT in einer Servicemeldung als kritisch ein", () => {
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret" },
    undefined,
    failedSnapshot({
      reachable: true,
      devices: [],
      serviceMessages: [{ source: "CCU Servicemeldung", detail: "Windrad Osten:0: ERROR_OVERHEAT" }],
      counters: {
        devices: 1,
        lowBattery: 0,
        unreachable: 0,
        configPending: 0,
        serviceMessages: 1,
        alarmMessages: 0
      }
    })
  );
  const serviceMessages = checks.find((check) => check.id === "service-messages");

  assert.equal(serviceMessages?.status, "critical");
  assert.match(serviceMessages?.recommendation ?? "", /Überhitzung zeitnah prüfen/);
});

test("stuft Sabotagehinweise als kritische Servicemeldung ein", () => {
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret" },
    undefined,
    failedSnapshot({
      reachable: true,
      serviceMessages: [{ source: "CCU Servicemeldung", detail: "Fenster Keller:0: SABOTAGE" }],
      counters: {
        devices: 1,
        lowBattery: 0,
        unreachable: 0,
        configPending: 0,
        serviceMessages: 1,
        alarmMessages: 0
      }
    })
  );
  const serviceMessages = checks.find((check) => check.id === "service-messages");

  assert.equal(serviceMessages?.status, "critical");
  assert.match(serviceMessages?.recommendation ?? "", /Sicherheits-|Manipulationsmeldung/);
});

test("zeigt niedrige Batterie nur im Batterie-Prüfpunkt und als Hinweis", () => {
  const batteryEvidence = { source: "CCU Servicemeldung", detail: "Fenster Keller: Batterie niedrig" };
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret" },
    undefined,
    failedSnapshot({
      reachable: true,
      devices: [{
        name: "Fenster Keller",
        type: "HmIP-SWDO",
        lowBattery: true,
        unreachable: false,
        configPending: false,
        evidence: [batteryEvidence]
      }],
      serviceMessages: [batteryEvidence],
      counters: {
        devices: 1,
        lowBattery: 1,
        unreachable: 0,
        configPending: 0,
        serviceMessages: 1,
        alarmMessages: 0
      }
    })
  );

  assert.equal(checks.find((check) => check.id === "batteries")?.status, "warning");
  assert.equal(checks.find((check) => check.id === "service-messages")?.status, "ok");
  assert.equal(checks.find((check) => check.id === "service-messages")?.evidence.length, 0);
});

test("stuft ein nicht erreichbares Funk-Gateway als kritisch ein", () => {
  const gatewayEvidence = { source: "CCU Servicemeldung", detail: "Funk-Gateway Obergeschoss: Gerätekommunikation gestört" };
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret" },
    undefined,
    failedSnapshot({
      reachable: true,
      devices: [{
        name: "Funk-Gateway Obergeschoss",
        type: "HMLGW2",
        lowBattery: false,
        unreachable: true,
        configPending: false,
        evidence: [gatewayEvidence]
      }],
      serviceMessages: [gatewayEvidence],
      counters: {
        devices: 1,
        lowBattery: 0,
        unreachable: 1,
        configPending: 0,
        serviceMessages: 1,
        alarmMessages: 0
      }
    })
  );

  const reachability = checks.find((check) => check.id === "reachability");
  assert.equal(reachability?.status, "critical");
  assert.match(reachability?.summary ?? "", /Funk-Gateway/);
  assert.match(reachability?.recommendation ?? "", /Stromversorgung/);
  assert.equal(checks.find((check) => check.id === "service-messages")?.status, "ok");
});

test("erklärt, dass Browser und Analyzer unterschiedliche Netzwerkwege nutzen", () => {
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret" },
    undefined,
    failedSnapshot({
      webUiReachable: false,
      errorCode: "network"
    })
  );
  const connection = checks.find((check) => check.id === "ccu-connection");

  assert.equal(connection?.status, "critical");
  assert.match(connection?.summary ?? "", /Browser unterscheiden/);
  assert.match(connection?.details.join(" ") ?? "", /nicht von deinem PC/);
});

test("erklärt bei erreichbarer WebUI einen XML-API-Timeout statt eines Netzwerkfehlers", () => {
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret", xmlApiToken: "token12345" },
    undefined,
    failedSnapshot({
      webUiReachable: true,
      xmlApiReachable: false,
      authentication: "not-tested",
      errorCode: "timeout",
      diagnostics: [
        { step: "Netzwerk / WebUI", status: "ok", detail: "HTTP 200" },
        { step: "XML-API Geräteliste", status: "failed", detail: "statelist.cgi antwortete nicht innerhalb von 30 Sekunden." }
      ]
    })
  );
  const xmlApi = checks.find((check) => check.id === "xml-api");

  assert.match(xmlApi?.recommendation ?? "", /XML-API-Geräteliste antwortet zu langsam/);
  assert.doesNotMatch(xmlApi?.recommendation ?? "", /Firewall/);
});

test("ordnet erhöhten Duty Cycle auch ohne Sniffer verständlich ein", () => {
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret" },
    undefined,
    {
      ...failedSnapshot({}),
      reachable: true,
      dutyCycle: 62,
      counters: {
        devices: 1,
        lowBattery: 0,
        unreachable: 0,
        configPending: 0,
        serviceMessages: 0,
        alarmMessages: 0
      }
    }
  );
  const dutyCycle = checks.find((check) => check.id === "duty-cycle");

  assert.equal(dutyCycle?.status, "improvement");
  assert.match(dutyCycle?.recommendation ?? "", /CCU-Wert beobachten/);
  assert.match(dutyCycle?.recommendation ?? "", /Geräte-Aufteilung.*ohne Sniffer nicht belegbar/);
  assert.doesNotMatch(dutyCycle?.recommendation ?? "", /DC-Analyzer/);
  assert.match(dutyCycle?.summary ?? "", /CCU meldet/);
  assert.equal(dutyCycle?.evidence[0]?.source, "CCU XML-API Duty Cycle");
  assert.match(dutyCycle?.details.join(" "), /keine belegbare Aufteilung/);
  assert.match(dutyCycle?.details.join(" "), /Nächste Schritte ohne Sniffer/);
});

test("verweist bei aktiviertem Sniffer auf die Verursacheranalyse", () => {
  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", ccuUser: "Admin", ccuPassword: "secret", snifferEnabled: true, snifferPort: "/dev/ttyUSB0" },
    undefined,
    {
      ...failedSnapshot({}),
      reachable: true,
      dutyCycle: 62,
      counters: {
        devices: 1,
        lowBattery: 0,
        unreachable: 0,
        configPending: 0,
        serviceMessages: 0,
        alarmMessages: 0
      }
    }
  );

  const dutyCycle = checks.find((check) => check.id === "duty-cycle");
  assert.match(dutyCycle?.recommendation ?? "", /DC-Analyzer/);
  assert.match(dutyCycle?.recommendation ?? "", /CCU-Wert/);
  assert.match(dutyCycle?.details.join(" ") ?? "", /Nächster Schritt mit Sniffer/);
});

test("bewertet ein einzelnes schwaches Sniffer-Telegramm noch nicht als belastbaren Beleg", () => {
  const sniffer: SnifferSnapshot = {
    checkedAt: "2026-06-13T10:00:00.000Z",
    port: "/dev/ttyUSB0",
    configured: true,
    connected: true,
    readerActive: true,
    source: "test",
    status: {
      state: "telegrams",
      label: "Funktelegramme werden empfangen",
      detail: "1 Homematic-Telegramm im aktuellen 60-Minuten-Fenster erkannt."
    },
    summary: {
      rawLines: 1,
      validLines: 1,
      invalidLines: 0,
      protocolCompatible: true,
      telegrams: 1,
      rssiSamples: 0,
      devices: 1,
      dutyCycle: 0
    },
    devices: [
      {
        address: "ABC123",
        name: "Testgerät",
        telegrams: 1,
        dutyCycle: 0,
        dutyShare: 100,
        sendTimeMs: 10,
        avgRssi: -100,
        lastSeen: "2026-06-13T10:00:00.000Z"
      }
    ],
    events: [],
    rssiNoise: [],
    diagnostics: []
  };

  const signalQuality = createAnalysis(
    { snifferPort: "/dev/ttyUSB0" },
    undefined,
    undefined,
    undefined,
    undefined,
    sniffer
  ).find((check) => check.id === "signal-strength");

  assert.equal(signalQuality?.status, "improvement");
  assert.match(signalQuality?.summary ?? "", /mindestens 3/);
  assert.match(signalQuality?.recommendation ?? "", /30 bis 60 Minuten/);
});

test("bewertet Wochen alte Collector-Logs nicht als aktuellen Zustand", () => {
  const staleCollector: CollectorPayload = {
    host: "Homematic-raspi",
    collectedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    logs: ["Jun 1 10:00:00 error: alter Fehler"],
    network: {
      connections: ["192.168.1.10:1234 192.168.1.22:8181 ESTABLISHED"]
    }
  };

  const checks = createAnalysis(
    { ccuHost: "192.168.1.22", sshUser: "root" },
    staleCollector
  );
  const logs = checks.find((check) => check.id === "logs");
  const externalAccess = checks.find((check) => check.id === "external-access");

  assert.equal(logs?.status, "unavailable");
  assert.match(logs?.summary ?? "", /früher erkannt/);
  assert.match(logs?.recommendation ?? "", /bereits eingerichtet/);
  assert.equal(externalAccess?.status, "unavailable");
});

test("wertet UNREACH=false im Collector-Log als unauffällige Entwarnung", () => {
  const collector: CollectorPayload = {
    host: "Homematic-raspi",
    collectedAt: new Date().toISOString(),
    logs: [
      'Jun 16 19:14:02 Homematic-raspi local0.info ReGaHss: Info: Event="0001D569A581EA:0"."UNREACH"=false [execute():iseXmlRpc.cpp:334]'
    ]
  };

  const logs = createAnalysis(
    { ccuHost: "192.168.1.22", sshUser: "root" },
    collector
  ).find((check) => check.id === "logs");

  assert.equal(logs?.status, "ok");
  assert.match(logs?.summary ?? "", /keine belegbaren Fehler/);
  assert.equal(logs?.evidence.length, 0);
});

test("wertet ReGa XML-API Lesehinweise als unauffällig", () => {
  const collector: CollectorPayload = {
    host: "Homematic-raspi",
    collectedAt: new Date().toISOString(),
    logs: [
      "Jul 21 14:03:01 Homematic-raspi local0.info ReGaHss: Info: metadata property 'UNIT' does not exist [GetUnitProperty():iseDOMdp.cpp:390]",
      "Jul 21 14:03:01 Homematic-raspi local0.info ReGaHss: Info: read flag is not set; operations = 4 [ReadValue():iseDOMdpHSS.cpp:133]"
    ]
  };

  const logs = createAnalysis(
    { ccuHost: "192.168.1.22", sshUser: "root" },
    collector
  ).find((check) => check.id === "logs");

  assert.equal(logs?.status, "ok");
  assert.match(logs?.summary ?? "", /keine belegbaren Fehler/);
  assert.equal(logs?.evidence.length, 0);
});

test("erklärt aktive CCU-Verbindungen mit lokal aufgelöstem Gerätenamen", () => {
  const collector: CollectorPayload = {
    host: "Homematic-raspi",
    collectedAt: new Date().toISOString(),
    network: {
      connections: [
        "tcp 0 0 192.168.1.22:2010 192.168.1.78:55964 ESTABLISHED 1541/lighttpd",
        "tcp 0 0 192.168.1.22:8181 192.168.1.78:55965 ESTABLISHED 1541/lighttpd"
      ]
    }
  };

  const externalAccess = createAnalysis(
    { ccuHost: "192.168.1.22", sshUser: "root" },
    collector,
    undefined,
    undefined,
    undefined,
    undefined,
    { "192.168.1.78": "iobroker.fritz.box" }
  ).find((check) => check.id === "external-access");

  assert.equal(externalAccess?.title, "Zugriffe anderer Systeme auf die CCU");
  assert.match(externalAccess?.summary ?? "", /iobroker\.fritz\.box \(192\.168\.1\.78\)/);
  assert.match(externalAccess?.summary ?? "", /2 Verbindungen/);
  assert.match(externalAccess?.summary ?? "", /HmIP-RPC/);
  assert.match(externalAccess?.evidence[0]?.detail ?? "", /iobroker\.fritz\.box \(192\.168\.1\.78\)/);
  assert.match(externalAccess?.evidence[0]?.detail ?? "", /Gerätename deutet auf ioBroker hin/);
  assert.match(externalAccess?.evidence[0]?.detail ?? "", /HmIP-RPC/);
  assert.match(externalAccess?.evidence[0]?.detail ?? "", /XML-API\/ReGa/);
  assert.equal(externalAccess?.evidence.some((evidence) => evidence.source === "Verbindungszeile"), false);
});

test("wertet viele lokale BidCos-RPC-Verbindungen ohne weitere Belege nicht als Warnung", () => {
  const collector: CollectorPayload = {
    host: "Homematic-raspi",
    collectedAt: new Date().toISOString(),
    network: {
      connections: Array.from({ length: 12 }, (_, index) => `tcp 0 0 192.168.1.22:2001 10.200.201.122:${55000 + index} ESTABLISHED 1541/lighttpd`)
    }
  };

  const externalAccess = createAnalysis(
    { ccuHost: "192.168.1.22", sshUser: "root" },
    collector
  ).find((check) => check.id === "external-access");

  assert.equal(externalAccess?.status, "ok");
  assert.match(externalAccess?.summary ?? "", /Anzahl allein ist kein Fehler/);
  assert.match(externalAccess?.recommendation ?? "", /Kein Handlungsbedarf allein aus der Anzahl/);
});

test("kennzeichnet eine nicht auflösbare lokale IP ohne Vermutung", () => {
  const collector: CollectorPayload = {
    host: "Homematic-raspi",
    collectedAt: new Date().toISOString(),
    network: {
      connections: ["tcp 0 0 192.168.1.22:80 192.168.1.90:40000 ESTABLISHED 1541/lighttpd"]
    }
  };

  const externalAccess = createAnalysis(
    { ccuHost: "192.168.1.22", sshUser: "root" },
    collector
  ).find((check) => check.id === "external-access");

  assert.match(externalAccess?.summary ?? "", /DNS-Name nicht auflösbar/);
  assert.match(externalAccess?.evidence[0]?.detail ?? "", /Gerät im Heimnetz/);
  assert.match(externalAccess?.evidence[0]?.detail ?? "", /Gerätename konnte im lokalen Netz nicht aufgelöst werden/);
  assert.doesNotMatch(externalAccess?.evidence[0]?.detail ?? "", /ioBroker|Home Assistant/);
});

test("zeigt ein verfügbares OpenCCU-Update als Wartungshinweis", () => {
  const centralRelease = createAnalysis(
    {},
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    {},
    {
      available: true,
      installedVersion: "3.81.7.20250125",
      latestVersion: "3.87.6.20260614",
      product: "OpenCCU",
      source: "openccu",
      url: "https://github.com/OpenCCU/OpenCCU/releases/tag/3.87.6.20260614",
      checkedAt: "2026-06-15T10:00:00.000Z"
    }
  ).find((check) => check.id === "central-release");

  assert.equal(centralRelease?.status, "warning");
  assert.match(centralRelease?.summary ?? "", /3\.87\.6\.20260614/);
  assert.match(centralRelease?.evidence[0]?.detail ?? "", /3\.81\.7\.20250125/);
  assert.match(centralRelease?.recommendation ?? "", /Backup/);
});

test("rät ohne installierte Zentralenversion kein Update", () => {
  const centralRelease = createAnalysis(
    {},
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    {},
    {
      available: false,
      latestVersion: "3.87.6.20260614",
      source: "openccu",
      url: "https://github.com/OpenCCU/OpenCCU/releases",
      checkedAt: "2026-06-15T10:00:00.000Z"
    }
  ).find((check) => check.id === "central-release");

  assert.equal(centralRelease?.status, "unavailable");
  assert.match(centralRelease?.summary ?? "", /kein Update behauptet/);
  assert.match(centralRelease?.recommendation ?? "", /Collector/);
  assert.doesNotMatch(centralRelease?.summary ?? "", /Aktuell verfügbar/);
});

test("zeigt Diagnose, wenn die Zentralenversion live nicht gelesen wurde", () => {
  const centralRelease = createAnalysis(
    {},
    undefined,
    {
      reachable: true,
      xmlApiInstalled: true,
      source: "xml-api",
      collectedAt: "2026-06-17T11:00:00.000Z",
      devices: [],
      serviceMessages: [],
      alarmMessages: [],
      counters: {
        devices: 0,
        lowBattery: 0,
        unreachable: 0,
        configPending: 0,
        serviceMessages: 0,
        alarmMessages: 0
      },
      diagnostics: [{
        step: "Zentralenversion",
        status: "skipped",
        detail: "Die CCU-Live-Verbindung ist ok. Die installierte Zentralenversion wurde in den geprüften WebUI-Seiten noch nicht eindeutig gefunden."
      }]
    },
    undefined,
    undefined,
    undefined,
    {},
    {
      available: false,
      latestVersion: "3.87.6.20260614",
      source: "openccu",
      url: "https://github.com/OpenCCU/OpenCCU/releases",
      checkedAt: "2026-06-17T11:00:00.000Z"
    }
  ).find((check) => check.id === "central-release");

  assert.equal(centralRelease?.status, "unavailable");
  assert.equal(centralRelease?.evidence.some((evidence) => evidence.source === "Zentralenversion"), true);
});

test("meldet OpenCCU als aktuell, wenn WebUI-Version dem Release entspricht", () => {
  const centralRelease = createAnalysis(
    {},
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    {},
    {
      available: false,
      installedVersion: "3.87.6.20260614",
      latestVersion: "3.87.6.20260614",
      product: "OpenCCU",
      source: "openccu",
      url: "https://github.com/OpenCCU/OpenCCU/releases/tag/3.87.6.20260614",
      checkedAt: "2026-06-17T10:00:00.000Z"
    }
  ).find((check) => check.id === "central-release");

  assert.equal(centralRelease?.status, "ok");
  assert.match(centralRelease?.summary ?? "", /aktuell/);
  assert.match(centralRelease?.evidence[0]?.detail ?? "", /Installiert: OpenCCU 3\.87\.6\.20260614/);
});

test("zeigt von der CCU gemeldete Geräte-Firmwareupdates mit Namen", () => {
  const collector: CollectorPayload = {
    collectedAt: new Date().toISOString(),
    deviceFirmware: [
      "DEVICE_FIRMWARE|interface=HmIP-RF|address=001ABC|type=HmIP-PSM|installed=2.6.2|available=2.8.6|state=READY_FOR_UPDATE|updatable=true"
    ]
  };
  const masterdata = {
    collectedAt: new Date().toISOString(),
    deviceCount: 1,
    devices: [{ name: "Steckdose Küche", address: "001ABC", type: "HmIP-PSM", firmware: "2.6.2" }]
  };

  const firmware = createAnalysis({}, collector, undefined, masterdata)
    .find((check) => check.id === "firmware-overview");

  assert.equal(firmware?.status, "warning");
  assert.match(firmware?.summary ?? "", /1 Gerät/);
  assert.match(firmware?.evidence[0]?.detail ?? "", /Steckdose Küche/);
  assert.match(firmware?.evidence[0]?.detail ?? "", /installiert 2\.6\.2, verfügbar 2\.8\.6/);
});

test("zeigt den originalen CCU3-Release getrennt von OpenCCU", () => {
  const centralRelease = createAnalysis(
    {},
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    {},
    {
      available: true,
      installedVersion: "3.81.7",
      latestVersion: "3.87.6",
      product: "HM-CCU3",
      source: "ccu3",
      url: "https://homematic-ip.com/de/downloads",
      checkedAt: "2026-06-15T10:00:00.000Z"
    }
  ).find((check) => check.id === "central-release");

  assert.equal(centralRelease?.title, "CCU3 Update");
  assert.match(centralRelease?.evidence[0]?.source ?? "", /CCU3/);
  assert.doesNotMatch(centralRelease?.summary ?? "", /OpenCCU/);
});

test("blendet die HmIP-Routing-Prüfung nur bei aktivierter Funktion ein", () => {
  const disabledChecks = createAnalysis({});
  const enabledChecks = createAnalysis({ hmipRoutingEnabled: true });

  assert.equal(disabledChecks.some((check) => check.id === "routing-topology"), false);
  assert.equal(enabledChecks.some((check) => check.id === "routing-topology"), true);
});

test("erzeugt Update-Kachel für CCU-Addons wie CUxD", () => {
  const checks = createAnalysis(
    {},
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    {},
    undefined,
    [
      {
        name: "CUxD",
        installedVersion: "2.10.1",
        latestVersion: "2.11.0",
        available: true,
        url: "https://github.com/jens-maus/cuxd/releases",
        checkedAt: "2026-08-18T10:00:00.000Z"
      }
    ]
  );

  const cuxdCheck = checks.find((check) => check.id === "addon-release-cuxd");
  assert.ok(cuxdCheck);
  assert.equal(cuxdCheck.title, "CUxD Update");
  assert.equal(cuxdCheck.status, "warning");
  assert.match(cuxdCheck.summary, /2\.11\.0/);
  assert.equal(cuxdCheck.evidence[0]?.source, "GitHub Add-on Release");
  assert.match(cuxdCheck.evidence[0]?.detail ?? "", /Installiert: 2\.10\.1/);
});

test("zeigt CCU-Addon als aktuell an, wenn kein Update vorliegt", () => {
  const checks = createAnalysis(
    {},
    undefined,
    undefined,
    undefined,
    undefined,
    undefined,
    {},
    undefined,
    [
      {
        name: "XML-API",
        installedVersion: "2.3",
        latestVersion: "2.3",
        available: false,
        url: "https://github.com/homematic-community/XML-API/releases",
        checkedAt: "2026-08-18T10:00:00.000Z"
      }
    ]
  );

  const xmlCheck = checks.find((check) => check.id === "addon-release-xml-api");
  assert.ok(xmlCheck);
  assert.equal(xmlCheck.status, "ok");
  assert.match(xmlCheck.summary, /aktuell/);
});
