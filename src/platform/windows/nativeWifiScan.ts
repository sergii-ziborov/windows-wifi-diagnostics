import type { CollectorSourceStatus } from '../../collector/types';
import { runPowerShell } from './powershell';

const DEFAULT_SCAN_TIMEOUT_MS = 8000;

export async function requestNativeWifiScan(): Promise<CollectorSourceStatus> {
  try {
    const { stdout } = await runPowerShell(buildNativeWifiScanScript(), DEFAULT_SCAN_TIMEOUT_MS);
    const detail = compactDetail(stdout);

    return {
      name: 'windows_native_wifi_scan',
      available: hasSuccessfulScan(detail),
      detail: detail || 'scan request returned no detail'
    };
  } catch (error) {
    return {
      name: 'windows_native_wifi_scan',
      available: false,
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

export function buildNativeWifiScanScript(): string {
  return `
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Monitor {
  public static class NativeWifiScanner {
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
    private static extern uint WlanScan(
      IntPtr hClientHandle,
      ref Guid pInterfaceGuid,
      IntPtr pDot11Ssid,
      IntPtr pIeData,
      IntPtr pReserved
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

    public static string ScanAll() {
      IntPtr clientHandle = IntPtr.Zero;
      IntPtr interfaceList = IntPtr.Zero;
      uint negotiatedVersion = 0;
      uint openResult = WlanOpenHandle(WlanClientVersionLonghorn, IntPtr.Zero, out negotiatedVersion, out clientHandle);

      if (openResult != 0) {
        return "open_error=" + openResult.ToString(CultureInfo.InvariantCulture);
      }

      try {
        uint enumResult = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out interfaceList);
        if (enumResult != 0) {
          return "enum_error=" + enumResult.ToString(CultureInfo.InvariantCulture);
        }

        int numberOfItems = Marshal.ReadInt32(interfaceList, 0);
        int itemSize = Marshal.SizeOf(typeof(WlanInterfaceInfo));
        long firstItemOffset = interfaceList.ToInt64() + 8;
        List<string> results = new List<string>();

        for (int index = 0; index < numberOfItems; index++) {
          IntPtr itemPtr = new IntPtr(firstItemOffset + ((long)index * itemSize));
          WlanInterfaceInfo info = (WlanInterfaceInfo)Marshal.PtrToStructure(itemPtr, typeof(WlanInterfaceInfo));
          Guid interfaceGuid = info.InterfaceGuid;
          uint scanResult = WlanScan(clientHandle, ref interfaceGuid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

          results.Add(
            scanResult.ToString(CultureInfo.InvariantCulture) + ":" +
            interfaceGuid.ToString("D") + ":" +
            Clean(info.InterfaceDescription)
          );
        }

        return "interface_count=" + numberOfItems.ToString(CultureInfo.InvariantCulture) +
          ";scan_results=" + string.Join("|", results.ToArray());
      } finally {
        if (interfaceList != IntPtr.Zero) {
          WlanFreeMemory(interfaceList);
        }

        if (clientHandle != IntPtr.Zero) {
          WlanCloseHandle(clientHandle, IntPtr.Zero);
        }
      }
    }

    private static string Clean(string value) {
      if (value == null) {
        return "";
      }

      return value.Replace("|", " ").Replace(";", " ").Replace(":", " ").Trim();
    }
  }
}
'@
[Monitor.NativeWifiScanner]::ScanAll()
`;
}

function compactDetail(stdout: string): string {
  return stdout.trim().replace(/\s+/g, ' ');
}

function hasSuccessfulScan(detail: string): boolean {
  const scanResults = detail.match(/scan_results=([^;]+)/)?.[1].split('|') ?? [];
  return scanResults.some((result) => result.startsWith('0:'));
}
