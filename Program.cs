using MyMemory_x64;
using Offsets;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WoWSniffer
{
  internal class Program
  {
    public static int m_WoWPID = 0;
    public static MemoryStream m_Packets = new MemoryStream();
    private const int QuickEditMode = 64;
    private const int ExtendedFlags = 128;
    public const int STD_INPUT_HANDLE = -10;

    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out int lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, int ioMode);

    public static void DisableQuickEdit()
    {
      IntPtr stdHandle = Program.GetStdHandle(-10);
      int lpMode;
      if (!Program.GetConsoleMode(stdHandle, out lpMode))
        return;
      int ioMode = lpMode & -193;
      Program.SetConsoleMode(stdHandle, ioMode);
    }

    public static Dictionary<string, int> GetWoWProcessList()
    {
      Dictionary<string, int> dictionary = new Dictionary<string, int>();
      foreach (Process process in Process.GetProcesses())
      {
        if ((process.ProcessName.ToUpper().Contains("WOW") || process.ProcessName.ToUpper().Contains("WORLD") || (process.ProcessName.ToUpper().Contains("ASHRAN") || process.ProcessName.ToUpper().Contains("6.0.3"))) && (!process.ProcessName.Contains("vshost") && !process.ProcessName.Contains("BrowserProxy") && (!process.ProcessName.Contains("worldserver") && !process.ProcessName.Contains("VoiceProxy"))))
        {
          if (!process.ProcessName.Contains("WowPacketParser"))
          {
            try
            {
              string fileName = Process.GetProcessById(process.Id).MainModule.FileName;
              if (new RemoteProcess().Open((uint) process.Id))
              {
                if (NativeFile.GetFileInfo(fileName).Version.Revision != Misc.Build)
                  continue;
              }
              else
                continue;
            }
            catch (Exception ex)
            {
              ex.GetType();
            }
            dictionary.Add(process.ProcessName + " (" + Misc.Patch + "." + Misc.Build.ToString() + ")-" + process.Id.ToString(), process.Id);
          }
        }
      }
      return dictionary;
    }

    public static byte[] StringToByteArrayFastest(string hex)
    {
      if (hex.Length % 2 == 1)
        throw new Exception("The binary key cannot have an odd number of digits");
      byte[] numArray = new byte[hex.Length >> 1];
      for (int index = 0; index < hex.Length >> 1; ++index)
        numArray[index] = (byte) ((Program.GetHexVal(hex[index << 1]) << 4) + Program.GetHexVal(hex[(index << 1) + 1]));
      return numArray;
    }

    public static int GetHexVal(char hex)
    {
      int num = (int) hex;
      return num - (num < 58 ? 48 : 55);
    }

    public static void SelectProcess(KeyValuePair<string, int> p_Process)
    {
      string str = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
      string path = string.Format("{0}.{1}_", (object) Misc.Patch, (object) Misc.Build) + str + ".pkt";
      try
      {
        WoWConnection.g_PacketOutput = new BinaryWriter((Stream) File.Open(path, FileMode.OpenOrCreate));
        byte[] buffer = new byte[40];
        WoWConnection.g_PacketOutput.Write('P');
        WoWConnection.g_PacketOutput.Write('K');
        WoWConnection.g_PacketOutput.Write('T');
        WoWConnection.g_PacketOutput.Write((ushort) 769);
        WoWConnection.g_PacketOutput.Write((byte) 21);
        WoWConnection.g_PacketOutput.Write((uint) Misc.Build);
        WoWConnection.g_PacketOutput.Write('e');
        WoWConnection.g_PacketOutput.Write('n');
        WoWConnection.g_PacketOutput.Write('U');
        WoWConnection.g_PacketOutput.Write('S');
        WoWConnection.g_PacketOutput.Write(buffer);
        WoWConnection.g_PacketOutput.Write((uint) WoWConnection.GetCurrentTimeStamp());
        WoWConnection.g_PacketOutput.Write((uint) Environment.TickCount);
        WoWConnection.g_PacketOutput.Write(0U);
        WoWConnection.g_PacketOutput.Flush();
      }
      catch (Exception ex)
      {
        Helper.WriteError("Cannot open/write to file \"" + path + "\": " + ex.Message);
      }
    }

    private static void Main(string[] args)
    {
      Program.DisableQuickEdit();

      Console.WriteLine("_____________World of Warcraft___________        ");
      Console.WriteLine("                   _   _                         ");
      Console.WriteLine("    /\\            | | (_)                       ");
      Console.WriteLine("   /  \\   _ __ ___| |_ _ _   _ _ __ ___         ");
      Console.WriteLine("  / /\\ \\ | '__/ __| __| | | | | '_ ` _ \\      ");
      Console.WriteLine(" / ____ \\| | | (__| |_| | |_| | | | | | |       ");
      Console.WriteLine("/_/    \\_\\_|  \\___|\\__|_|\\__,_|_| |_| |_| \n");
      Console.WriteLine("___________WoW Client Launcher___________        ");
      Console.WriteLine("            https://arctium.io                 \n");
      Console.WriteLine("Mode: Sniffer                                  \n");

      Console.WriteLine(string.Format("Allowed build: {0}\n", (object) Misc.Build));
      Console.WriteLine("Current WoW instances running:");

      Dictionary<string, int> woWprocessList;
      do
      {
        woWprocessList = Program.GetWoWProcessList();
        foreach (KeyValuePair<string, int> keyValuePair in woWprocessList)
          Console.WriteLine(keyValuePair.Key);
        Thread.Sleep(100);
      }
      while (woWprocessList.Count == 0);
      while (WoWConnection.g_PacketOutput == null)
      {
        try
        {
          if (woWprocessList.Count == 1)
          {
            KeyValuePair<string, int> keyValuePair = woWprocessList.ElementAt<KeyValuePair<string, int>>(0);
            Console.WriteLine("Automatically selected: " + keyValuePair.Key);
            keyValuePair = woWprocessList.ElementAt<KeyValuePair<string, int>>(0);
            Program.m_WoWPID = keyValuePair.Value;
            Program.SelectProcess(woWprocessList.ElementAt<KeyValuePair<string, int>>(0));
          }
          else
          {
            Console.Write("Please enter the PID of the WoW instance you want to sniff: ");
            Program.m_WoWPID = Convert.ToInt32(Console.ReadLine());
            foreach (KeyValuePair<string, int> p_Process in woWprocessList)
            {
              if (p_Process.Value == Program.m_WoWPID)
                Program.SelectProcess(p_Process);
            }
          }
        }
        catch (Exception ex)
        {
          Console.WriteLine(ex.Message);
        }
      }
      Console.WriteLine();
      IList<LivePacketDevice> allLocalMachine = (IList<LivePacketDevice>) LivePacketDevice.AllLocalMachine;
      if (allLocalMachine.Count == 0)
      {
        Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
      }
      else
      {
        string str = "";
        int result1 = 0;
        if (File.Exists("./interface.cfg"))
        {
          str = File.ReadAllText("./interface.cfg");
          Console.WriteLine("Trying to automatically select interface..");
        }
        for (int index = 0; index != allLocalMachine.Count; ++index)
        {
          LivePacketDevice livePacketDevice = allLocalMachine[index];
          if (str.Length > 1 && livePacketDevice.Name.EndsWith(str))
          {
            Console.WriteLine("Automatically selected interface:");
            Console.WriteLine(livePacketDevice.Name + " (" + livePacketDevice.Description + ")");
            result1 = index + 1;
            break;
          }
        }
        if (result1 == 0)
        {
          int num;
          for (int index = 0; index != allLocalMachine.Count; ++index)
          {
            LivePacketDevice livePacketDevice = allLocalMachine[index];
            foreach (DeviceAddress address in livePacketDevice.Addresses)
            {
              if (address.Address != null)
                Console.WriteLine("\tAddress: " + address.Address?.ToString());
            }
            Console.WriteLine();
            num = index + 1;
            Console.Write(num.ToString() + ". " + livePacketDevice.Name);
            if (livePacketDevice.Description != null)
              Console.WriteLine(" (" + livePacketDevice.Description + ")");
            else
              Console.WriteLine(" (No description available)");
          }
          do
          {
            num = allLocalMachine.Count;
            Console.WriteLine("Enter the interface number (1-" + num.ToString() + "):");
            if (!int.TryParse(Console.ReadLine(), out result1) || result1 < 1 || result1 > allLocalMachine.Count)
              result1 = 0;
          }
          while (result1 == 0);
        }
        PacketDevice packetDevice = (PacketDevice) allLocalMachine[result1 - 1];
        using (PacketCommunicator packetCommunicator = packetDevice.Open(65536, PacketDeviceOpenAttributes.MaximumResponsiveness, 10000))
        {
          if (packetCommunicator.DataLink.Kind != DataLinkKind.Ethernet)
          {
            Console.WriteLine("This program works only on Ethernet networks.");
          }
          else
          {
            using (BerkeleyPacketFilter filter = packetCommunicator.CreateFilter("tcp"))
              packetCommunicator.SetFilter(filter);
            Console.WriteLine("Listening on " + packetDevice.Description + "...");
            ConcurrentQueue<Packet> l_PacketsQueue = new ConcurrentQueue<Packet>();
            new Thread((ThreadStart) (() =>
            {
              while (true)
              {
                do
                {
                  Console.Write("Command : ");
                }
                while (!Console.ReadLine().StartsWith("stop"));
                foreach (WoWConnection gList in WoWConnection.g_Lists)
                  gList.UpdateRecvBuffer();
                WoWConnection.g_Lists.Clear();
                WoWConnection.g_PacketOutput.Flush();
                WoWConnection.g_PacketOutput.Close();
                Environment.Exit(0);
              }
            })).Start();
            new Thread((ThreadStart) (() =>
            {
              while (true)
              {
                Packet result;
                while (l_PacketsQueue.TryDequeue(out result))
                {
                  if (result != null && result.Ethernet != null && (result.Ethernet.IpV4 != null && result.Ethernet.IpV4.Tcp != null) && result.Ethernet.IpV4.Tcp.Payload != null)
                  {
                    byte[] array = result.Ethernet.IpV4.Tcp.Payload.ToMemoryStream().ToArray();
                    IpV4Datagram ipV4 = result.Ethernet.IpV4;
                    if (ipV4 != null && ipV4.Transport != null)
                    {
                      WoWConnection woWconnection = WoWConnection.GetWoWConnection(ipV4.Destination.ToString(), ipV4.Transport.DestinationPort, ipV4.Source.ToString(), ipV4.Transport.SourcePort);
                      if (woWconnection == null && Encoding.ASCII.GetString(array).StartsWith("WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2"))
                        woWconnection = new WoWConnection(ipV4.Destination.ToString(), ipV4.Transport.DestinationPort, ipV4.Source.ToString(), ipV4.Transport.SourcePort);
                      if (woWconnection != null)
                      {
                        woWconnection.m_TcpReconstruction.ReassemblePacket(result);
                        woWconnection.UpdateSendBuffer();
                        woWconnection.UpdateRecvBuffer();
                        break;
                      }
                    }
                  }
                }
                Thread.Sleep(1);
              }
            })).Start();
            try
            {
              PacketCommunicatorReceiveResult packet1;
              while (true)
              {
                Packet packet2;
                do
                {
                  packet1 = packetCommunicator.ReceivePacket(out packet2);
                  if (packet1 == PacketCommunicatorReceiveResult.Ok)
                    goto label_55;
                }
                while (packet1 == PacketCommunicatorReceiveResult.Timeout);
                break;
label_55:
                l_PacketsQueue.Enqueue(packet2);
              }
              throw new InvalidOperationException("The result " + packet1.ToString() + " should never be reached here");
            }
            catch (Exception ex)
            {
              Console.WriteLine(ex.Source);
              Console.WriteLine(ex.Message);
              Console.WriteLine(ex.StackTrace);
            }
          }
        }
      }
    }

    public static string ByteArrayToString(byte[] ba)
    {
      return BitConverter.ToString(ba).Replace("-", "");
    }
  }
}
