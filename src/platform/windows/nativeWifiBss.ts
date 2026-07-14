import type { CollectorSourceStatus, EventContext, WindowsNativeBssEntry, WindowsNativeBssResult } from '../../collector/types';
import { runPowerShell } from './powershell';

const DEFAULT_BSS_TIMEOUT_MS = 10_000;

interface NativeBssJsonEntry {
  InterfaceGuid?: string | null;
  InterfaceDescription?: string | null;
  Ssid?: string | null;
  Bssid?: string | null;
  BssType?: string | null;
  PhyType?: string | null;
  RssiDbm?: number | null;
  LinkQuality?: number | null;
  CenterFrequencyKHz?: number | null;
  BeaconPeriodTu?: number | null;
  InRegDomain?: boolean | null;
  CapabilityInformation?: number | null;
  Timestamp?: string | null;
  HostTimestamp?: string | null;
  RatesMbps?: number[] | number | null;
  InformationElements?: {
    ByteLength?: number | null;
    ElementCount?: number | null;
    ElementIds?: number[] | number | null;
    Names?: string[] | string | null;
    ExtensionIds?: number[] | number | null;
    VendorOuis?: string[] | string | null;
    HasRsn?: boolean | null;
    HasWpa?: boolean | null;
    HasBssLoad?: boolean | null;
    HasCountry?: boolean | null;
    HasHt?: boolean | null;
    HasVht?: boolean | null;
    HasHe?: boolean | null;
    HasEht?: boolean | null;
  } | null;
}

export async function getNativeWifiBssEntries(_context: EventContext): Promise<WindowsNativeBssResult> {
  try {
    const { stdout } = await runPowerShell(buildNativeWifiBssScript(), DEFAULT_BSS_TIMEOUT_MS);
    const entries = parseNativeWifiBssEntries(stdout);

    return {
      source: {
        name: 'windows_native_bss_list',
        available: true,
        detail: `bssid_count=${entries.length};ie_bytes=${sumIeBytes(entries)}`
      },
      entries
    };
  } catch (error) {
    return {
      source: {
        name: 'windows_native_bss_list',
        available: false,
        detail: error instanceof Error ? error.message : String(error)
      },
      entries: []
    };
  }
}

export function parseNativeWifiBssEntries(output: string): WindowsNativeBssEntry[] {
  const trimmed = output.trim();
  if (!trimmed) {
    return [];
  }

  const parsed = JSON.parse(trimmed) as NativeBssJsonEntry | NativeBssJsonEntry[];
  const entries = Array.isArray(parsed) ? parsed : [parsed];

  return entries.map((entry) => ({
    interface_guid: normalizeString(entry.InterfaceGuid),
    interface_description: normalizeString(entry.InterfaceDescription),
    ssid: normalizeString(entry.Ssid),
    bssid: normalizeMac(entry.Bssid),
    native_bss: {
      interface_guid: normalizeString(entry.InterfaceGuid),
      interface_description: normalizeString(entry.InterfaceDescription),
      bss_type: normalizeString(entry.BssType),
      phy_type: normalizeString(entry.PhyType),
      rssi_dbm: numberOrNull(entry.RssiDbm),
      link_quality: numberOrNull(entry.LinkQuality),
      center_frequency_khz: numberOrNull(entry.CenterFrequencyKHz),
      beacon_period_tu: numberOrNull(entry.BeaconPeriodTu),
      in_reg_domain: typeof entry.InRegDomain === 'boolean' ? entry.InRegDomain : null,
      capability_information: numberOrNull(entry.CapabilityInformation),
      timestamp: normalizeString(entry.Timestamp),
      host_timestamp: normalizeString(entry.HostTimestamp),
      rates_mbps: arrayOfNumbers(entry.RatesMbps),
      information_elements: {
        byte_length: numberOrZero(entry.InformationElements?.ByteLength),
        element_count: numberOrZero(entry.InformationElements?.ElementCount),
        element_ids: arrayOfNumbers(entry.InformationElements?.ElementIds),
        names: arrayOfStrings(entry.InformationElements?.Names),
        extension_ids: arrayOfNumbers(entry.InformationElements?.ExtensionIds),
        vendor_ouis: arrayOfStrings(entry.InformationElements?.VendorOuis),
        has_rsn: Boolean(entry.InformationElements?.HasRsn),
        has_wpa: Boolean(entry.InformationElements?.HasWpa),
        has_bss_load: Boolean(entry.InformationElements?.HasBssLoad),
        has_country: Boolean(entry.InformationElements?.HasCountry),
        has_ht: Boolean(entry.InformationElements?.HasHt),
        has_vht: Boolean(entry.InformationElements?.HasVht),
        has_he: Boolean(entry.InformationElements?.HasHe),
        has_eht: Boolean(entry.InformationElements?.HasEht)
      }
    }
  }));
}

export function buildNativeWifiBssScript(): string {
  return `
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Monitor {
  public sealed class BssRecord {
    public string InterfaceGuid { get; set; }
    public string InterfaceDescription { get; set; }
    public string Ssid { get; set; }
    public string Bssid { get; set; }
    public string BssType { get; set; }
    public string PhyType { get; set; }
    public int RssiDbm { get; set; }
    public uint LinkQuality { get; set; }
    public uint CenterFrequencyKHz { get; set; }
    public ushort BeaconPeriodTu { get; set; }
    public bool InRegDomain { get; set; }
    public ushort CapabilityInformation { get; set; }
    public string Timestamp { get; set; }
    public string HostTimestamp { get; set; }
    public double[] RatesMbps { get; set; }
    public IeSummary InformationElements { get; set; }
  }

  public sealed class IeSummary {
    public int ByteLength { get; set; }
    public int ElementCount { get; set; }
    public int[] ElementIds { get; set; }
    public string[] Names { get; set; }
    public int[] ExtensionIds { get; set; }
    public string[] VendorOuis { get; set; }
    public bool HasRsn { get; set; }
    public bool HasWpa { get; set; }
    public bool HasBssLoad { get; set; }
    public bool HasCountry { get; set; }
    public bool HasHt { get; set; }
    public bool HasVht { get; set; }
    public bool HasHe { get; set; }
    public bool HasEht { get; set; }
  }

  public static class NativeWifiBssReader {
    private const uint WlanClientVersionLonghorn = 2;

    [DllImport("wlanapi.dll")]
    private static extern uint WlanOpenHandle(
      uint dwClientVersion,
      IntPtr pReserved,
      out uint pdwNegotiatedVersion,
      out IntPtr phClientHandle
    );

    [DllImport("wlanapi.dll")]
    private static extern uint WlanEnumInterfaces(
      IntPtr hClientHandle,
      IntPtr pReserved,
      out IntPtr ppInterfaceList
    );

    [DllImport("wlanapi.dll")]
    private static extern uint WlanGetNetworkBssList(
      IntPtr hClientHandle,
      ref Guid pInterfaceGuid,
      IntPtr pDot11Ssid,
      int dot11BssType,
      bool bSecurityEnabled,
      IntPtr pReserved,
      out IntPtr ppWlanBssList
    );

    [DllImport("wlanapi.dll")]
    private static extern void WlanFreeMemory(IntPtr pMemory);

    [DllImport("wlanapi.dll")]
    private static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WlanInterfaceInfo {
      public Guid InterfaceGuid;

      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
      public string InterfaceDescription;

      public int InterfaceState;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Dot11Ssid {
      public uint uSSIDLength;

      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
      public byte[] ucSSID;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanRateSet {
      public uint uRateSetLength;

      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
      public ushort[] usRateSet;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanBssEntry {
      public Dot11Ssid dot11Ssid;
      public uint uPhyId;

      [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
      public byte[] dot11Bssid;

      public int dot11BssType;
      public int dot11BssPhyType;
      public int lRssi;
      public uint uLinkQuality;
      public byte bInRegDomain;
      public ushort usBeaconPeriod;
      public ulong ullTimestamp;
      public ulong ullHostTimestamp;
      public ushort usCapabilityInformation;
      public uint ulChCenterFrequency;
      public WlanRateSet wlanRateSet;
      public uint ulIeOffset;
      public uint ulIeSize;
    }

    public static List<BssRecord> GetAll() {
      IntPtr clientHandle = IntPtr.Zero;
      IntPtr interfaceList = IntPtr.Zero;
      uint negotiatedVersion = 0;
      uint openResult = WlanOpenHandle(WlanClientVersionLonghorn, IntPtr.Zero, out negotiatedVersion, out clientHandle);

      if (openResult != 0) {
        throw new InvalidOperationException("WlanOpenHandle error " + openResult.ToString(CultureInfo.InvariantCulture));
      }

      try {
        uint enumResult = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out interfaceList);
        if (enumResult != 0) {
          throw new InvalidOperationException("WlanEnumInterfaces error " + enumResult.ToString(CultureInfo.InvariantCulture));
        }

        int numberOfItems = Marshal.ReadInt32(interfaceList, 0);
        int interfaceItemSize = Marshal.SizeOf(typeof(WlanInterfaceInfo));
        long firstInterfaceOffset = interfaceList.ToInt64() + 8;
        List<BssRecord> records = new List<BssRecord>();

        for (int index = 0; index < numberOfItems; index++) {
          IntPtr itemPtr = new IntPtr(firstInterfaceOffset + ((long)index * interfaceItemSize));
          WlanInterfaceInfo info = (WlanInterfaceInfo)Marshal.PtrToStructure(itemPtr, typeof(WlanInterfaceInfo));
          Guid interfaceGuid = info.InterfaceGuid;
          IntPtr bssList = IntPtr.Zero;
          uint bssResult = WlanGetNetworkBssList(clientHandle, ref interfaceGuid, IntPtr.Zero, 3, false, IntPtr.Zero, out bssList);

          if (bssResult != 0) {
            continue;
          }

          try {
            AddBssList(records, bssList, info);
          } finally {
            if (bssList != IntPtr.Zero) {
              WlanFreeMemory(bssList);
            }
          }
        }

        return records;
      } finally {
        if (interfaceList != IntPtr.Zero) {
          WlanFreeMemory(interfaceList);
        }

        if (clientHandle != IntPtr.Zero) {
          WlanCloseHandle(clientHandle, IntPtr.Zero);
        }
      }
    }

    private static void AddBssList(List<BssRecord> records, IntPtr bssList, WlanInterfaceInfo info) {
      int numberOfItems = Marshal.ReadInt32(bssList, 4);
      int entrySize = Marshal.SizeOf(typeof(WlanBssEntry));
      long firstEntryOffset = bssList.ToInt64() + 8;

      for (int index = 0; index < numberOfItems; index++) {
        IntPtr entryPtr = new IntPtr(firstEntryOffset + ((long)index * entrySize));
        WlanBssEntry entry = (WlanBssEntry)Marshal.PtrToStructure(entryPtr, typeof(WlanBssEntry));
        byte[] ieBytes = ReadInformationElements(entryPtr, entry);

        records.Add(new BssRecord {
          InterfaceGuid = info.InterfaceGuid.ToString("D"),
          InterfaceDescription = Clean(info.InterfaceDescription),
          Ssid = DecodeSsid(entry.dot11Ssid),
          Bssid = FormatMac(entry.dot11Bssid),
          BssType = FormatBssType(entry.dot11BssType),
          PhyType = FormatPhyType(entry.dot11BssPhyType),
          RssiDbm = entry.lRssi,
          LinkQuality = entry.uLinkQuality,
          CenterFrequencyKHz = entry.ulChCenterFrequency,
          BeaconPeriodTu = entry.usBeaconPeriod,
          InRegDomain = entry.bInRegDomain != 0,
          CapabilityInformation = entry.usCapabilityInformation,
          Timestamp = entry.ullTimestamp.ToString(CultureInfo.InvariantCulture),
          HostTimestamp = FormatFileTime(entry.ullHostTimestamp),
          RatesMbps = DecodeRates(entry.wlanRateSet),
          InformationElements = SummarizeInformationElements(ieBytes)
        });
      }
    }

    private static byte[] ReadInformationElements(IntPtr entryPtr, WlanBssEntry entry) {
      if (entry.ulIeOffset == 0 || entry.ulIeSize == 0 || entry.ulIeSize > 4096) {
        return new byte[0];
      }

      byte[] bytes = new byte[entry.ulIeSize];
      Marshal.Copy(new IntPtr(entryPtr.ToInt64() + entry.ulIeOffset), bytes, 0, bytes.Length);
      return bytes;
    }

    private static IeSummary SummarizeInformationElements(byte[] bytes) {
      HashSet<int> ids = new HashSet<int>();
      HashSet<int> extensionIds = new HashSet<int>();
      HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      HashSet<string> vendorOuis = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      bool hasWpa = false;
      int count = 0;
      int offset = 0;

      while (offset + 2 <= bytes.Length) {
        int id = bytes[offset];
        int length = bytes[offset + 1];
        int valueOffset = offset + 2;
        int nextOffset = valueOffset + length;

        if (nextOffset > bytes.Length) {
          break;
        }

        ids.Add(id);
        names.Add(FormatIeName(id));
        count++;

        if (id == 221 && length >= 3) {
          string oui = FormatOui(bytes, valueOffset);
          vendorOuis.Add(oui);
          if (length >= 4 && oui == "00:50:f2" && bytes[valueOffset + 3] == 1) {
            hasWpa = true;
          }
        }

        if (id == 255 && length >= 1) {
          int extensionId = bytes[valueOffset];
          extensionIds.Add(extensionId);
          names.Add("Extension " + extensionId.ToString(CultureInfo.InvariantCulture));
        }

        offset = nextOffset;
      }

      List<int> idList = new List<int>(ids);
      idList.Sort();
      List<int> extList = new List<int>(extensionIds);
      extList.Sort();
      List<string> nameList = new List<string>(names);
      nameList.Sort(StringComparer.OrdinalIgnoreCase);
      List<string> ouiList = new List<string>(vendorOuis);
      ouiList.Sort(StringComparer.OrdinalIgnoreCase);

      return new IeSummary {
        ByteLength = bytes.Length,
        ElementCount = count,
        ElementIds = idList.ToArray(),
        Names = nameList.ToArray(),
        ExtensionIds = extList.ToArray(),
        VendorOuis = ouiList.ToArray(),
        HasRsn = ids.Contains(48),
        HasWpa = hasWpa,
        HasBssLoad = ids.Contains(11),
        HasCountry = ids.Contains(7),
        HasHt = ids.Contains(45) || ids.Contains(61),
        HasVht = ids.Contains(191) || ids.Contains(192),
        HasHe = extensionIds.Contains(35) || extensionIds.Contains(36) || extensionIds.Contains(37) || extensionIds.Contains(38),
        HasEht = extensionIds.Contains(106) || extensionIds.Contains(107) || extensionIds.Contains(108)
      };
    }

    private static string FormatIeName(int id) {
      switch (id) {
        case 0: return "SSID";
        case 1: return "Supported rates";
        case 3: return "DS parameter set";
        case 5: return "TIM";
        case 7: return "Country";
        case 11: return "BSS load";
        case 32: return "Power constraint";
        case 45: return "HT capabilities";
        case 48: return "RSN";
        case 50: return "Extended supported rates";
        case 61: return "HT operation";
        case 70: return "RM enabled capabilities";
        case 107: return "Interworking";
        case 127: return "Extended capabilities";
        case 191: return "VHT capabilities";
        case 192: return "VHT operation";
        case 195: return "Transmit power envelope";
        case 201: return "Reduced neighbor report";
        case 221: return "Vendor specific";
        case 255: return "Extension";
        default: return "IE " + id.ToString(CultureInfo.InvariantCulture);
      }
    }

    private static string DecodeSsid(Dot11Ssid ssid) {
      if (ssid.ucSSID == null || ssid.uSSIDLength == 0) {
        return null;
      }

      int length = Math.Min((int)ssid.uSSIDLength, ssid.ucSSID.Length);
      return Encoding.UTF8.GetString(ssid.ucSSID, 0, length).TrimEnd('\\0');
    }

    private static string FormatMac(byte[] mac) {
      if (mac == null || mac.Length < 6) {
        return null;
      }

      return BitConverter.ToString(mac, 0, 6).Replace("-", ":").ToLowerInvariant();
    }

    private static string FormatOui(byte[] bytes, int offset) {
      if (offset + 3 > bytes.Length) {
        return "";
      }

      return bytes[offset].ToString("x2", CultureInfo.InvariantCulture) + ":" +
        bytes[offset + 1].ToString("x2", CultureInfo.InvariantCulture) + ":" +
        bytes[offset + 2].ToString("x2", CultureInfo.InvariantCulture);
    }

    private static double[] DecodeRates(WlanRateSet rateSet) {
      if (rateSet.usRateSet == null || rateSet.uRateSetLength == 0) {
        return new double[0];
      }

      int length = Math.Min((int)rateSet.uRateSetLength, rateSet.usRateSet.Length);
      List<double> rates = new List<double>();

      for (int index = 0; index < length; index++) {
        ushort raw = rateSet.usRateSet[index];
        ushort rateUnits = (ushort)(raw & 0x7fff);
        rates.Add(rateUnits * 0.5);
      }

      return rates.ToArray();
    }

    private static string FormatBssType(int value) {
      switch (value) {
        case 1: return "infrastructure";
        case 2: return "independent";
        case 3: return "any";
        default: return "unknown_" + value.ToString(CultureInfo.InvariantCulture);
      }
    }

    private static string FormatPhyType(int value) {
      switch (value) {
        case 1: return "fhss";
        case 2: return "dsss";
        case 3: return "irbaseband";
        case 4: return "ofdm";
        case 5: return "hrdsss";
        case 6: return "erp";
        case 7: return "ht";
        case 8: return "vht";
        case 9: return "dmg";
        case 10: return "he";
        case 11: return "eht";
        default: return "unknown_" + value.ToString(CultureInfo.InvariantCulture);
      }
    }

    private static string FormatFileTime(ulong value) {
      if (value == 0 || value > 9223372036854775807UL) {
        return null;
      }

      try {
        return DateTime.FromFileTimeUtc((long)value).ToString("o", CultureInfo.InvariantCulture);
      } catch {
        return value.ToString(CultureInfo.InvariantCulture);
      }
    }

    private static string Clean(string value) {
      if (value == null) {
        return null;
      }

      return value.Trim();
    }
  }
}
'@
@([Monitor.NativeWifiBssReader]::GetAll()) | ConvertTo-Json -Depth 8 -Compress
`;
}

function normalizeString(value: string | null | undefined): string | null {
  if (typeof value !== 'string') {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizeMac(value: string | null | undefined): string | null {
  return normalizeString(value)?.replace(/-/g, ':').toLowerCase() ?? null;
}

function numberOrNull(value: number | null | undefined): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function numberOrZero(value: number | null | undefined): number {
  return numberOrNull(value) ?? 0;
}

function arrayOfNumbers(value: number[] | number | null | undefined): number[] {
  const values = Array.isArray(value) ? value : typeof value === 'number' ? [value] : [];
  return values.filter((item) => Number.isFinite(item));
}

function arrayOfStrings(value: string[] | string | null | undefined): string[] {
  const values = Array.isArray(value) ? value : typeof value === 'string' ? [value] : [];
  return values.map((item) => item.trim()).filter((item) => item.length > 0);
}

function sumIeBytes(entries: WindowsNativeBssEntry[]): number {
  return entries.reduce((total, entry) => total + entry.native_bss.information_elements.byte_length, 0);
}
