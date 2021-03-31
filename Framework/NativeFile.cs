using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace WoWSniffer
{
  public static class NativeFile
  {
    public static unsafe NativeFile.NativeFileInfo GetFileInfo(string p_FileName)
    {
      if (!File.Exists(p_FileName))
        throw new FileNotFoundException();
      IntPtr lpdwHandle;
      int fileVersionInfoSize = NativeFile.GetFileVersionInfoSize(p_FileName, out lpdwHandle);
      IntPtr num = Marshal.AllocHGlobal(fileVersionInfoSize);
      try
      {
        if (!NativeFile.GetFileVersionInfo(p_FileName, lpdwHandle, fileVersionInfoSize, num))
          throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr lplpBuffer;
        int puLen;
        NativeFile.VerQueryValue(num, "\\", out lplpBuffer, out puLen);
        NativeFile.VS_FIXEDFILEINFO structure = (NativeFile.VS_FIXEDFILEINFO) Marshal.PtrToStructure(lplpBuffer, typeof (NativeFile.VS_FIXEDFILEINFO));
        Version version = new Version((int) structure.dwFileVersionMS >> 16, (int) structure.dwFileVersionMS & (int) ushort.MaxValue, (int) structure.dwFileVersionLS >> 16, (int) structure.dwFileVersionLS & (int) ushort.MaxValue);
        NameValueCollection stringTable = NativeFile.ParseStringTable((byte*) ((IntPtr) lplpBuffer.ToPointer() + puLen), fileVersionInfoSize - puLen);
        NativeFile.NativeFileInfo nativeFileInfo = new NativeFile.NativeFileInfo();
        nativeFileInfo.Version = version;
        nativeFileInfo.StringTable = stringTable;
        nativeFileInfo = nativeFileInfo;
        return nativeFileInfo;
      }
      finally
      {
        Marshal.FreeHGlobal(num);
      }
    }

    private static unsafe NameValueCollection ParseStringTable(
      byte* p_StringTable,
      int p_Lenght)
    {
      NameValueCollection nameValueCollection = new NameValueCollection();
      byte* numPtr1 = p_StringTable;
      int num1 = (int) *numPtr1;
      byte* numPtr2 = p_StringTable + p_Lenght;
      byte* numPtr3 = numPtr1 + 6;
      if (Marshal.PtrToStringUni(new IntPtr((void*) numPtr3), 14) != "StringFileInfo")
        throw new ArgumentException();
      byte* numPtr4 = numPtr3 + 30;
      int num2 = (int) *numPtr4;
      byte* numPtr5 = numPtr4 + 6;
      Marshal.PtrToStringUni(new IntPtr((void*) numPtr5), 8);
      byte* numPtr6 = numPtr5 + 18;
      while (numPtr6 < numPtr2)
      {
        short num3 = (short) *numPtr6;
        byte* numPtr7 = numPtr6 + 2;
        short num4 = (short) *numPtr7;
        byte* numPtr8 = numPtr7 + 2;
        short num5 = (short) *numPtr8;
        byte* numPtr9 = numPtr8 + 2;
        if (num3 != (short) 0)
        {
          if (num4 == (short) 0 || num5 != (short) 1)
          {
            numPtr6 = numPtr9 + (int) num3;
          }
          else
          {
            int num6 = (int) num3 - (int) num4 * 2 - 6;
            string name = Marshal.PtrToStringUni(new IntPtr((void*) numPtr9), num6 / 2).TrimEnd(new char[1]);
            byte* numPtr10 = numPtr9 + num6;
            string str = Marshal.PtrToStringUni(new IntPtr((void*) numPtr10), (int) num4).TrimEnd(new char[1]);
            numPtr6 = numPtr10 + (int) num4 * 2;
            if ((int) numPtr6 % 4 != 0)
              numPtr6 += 2;
            nameValueCollection.Add(name, str);
          }
        }
        else
          break;
      }
      return nameValueCollection;
    }

    [DllImport("version.dll", SetLastError = true)]
    private static extern int GetFileVersionInfoSize(string lptstrFilename, out IntPtr lpdwHandle);

    [DllImport("version.dll", SetLastError = true)]
    private static extern bool GetFileVersionInfo(
      string lptstrFilename,
      IntPtr dwHandle,
      int dwLen,
      IntPtr lpData);

    [DllImport("version.dll", SetLastError = true)]
    private static extern bool VerQueryValue(
      IntPtr pBlock,
      string lpSubBlock,
      out IntPtr lplpBuffer,
      out int puLen);

    public struct NativeFileInfo
    {
      public Version Version;
      public NameValueCollection StringTable;
    }

    private struct VS_FIXEDFILEINFO
    {
      public uint dwSignature;
      public uint dwStrucVersion;
      public uint dwFileVersionMS;
      public uint dwFileVersionLS;
      public uint dwProductVersionMS;
      public uint dwProductVersionLS;
      public uint dwFileFlagsMask;
      public uint dwFileFlags;
      public NativeFile.FileOS dwFileOS;
      public NativeFile.FileType dwFileType;
      public uint dwFileSubtype;
      public uint dwFileDateMS;
      public uint dwFileDateLS;
    }

    public enum FileOS : uint
    {
      Unknown = 0,
      DOS = 65536, // 0x00010000
      OS2_16 = 131072, // 0x00020000
      OS2_32 = 196608, // 0x00030000
      NT = 262144, // 0x00040000
      WindowsCE = 327680, // 0x00050000
    }

    public enum FileType : uint
    {
      Unknown = 0,
      Application = 1,
      DLL = 2,
      Driver = 3,
      Font = 4,
      VXD = 5,
      StaticLib = 7,
    }
  }
}
