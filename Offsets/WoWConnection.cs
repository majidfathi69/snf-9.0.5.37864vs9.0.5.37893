using Ionic.Zlib;
using MyMemory_x64;
using Offsets;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using WoWSniffer.Framework;

namespace WoWSniffer
{
  internal class WoWConnection
  {
    // skip verify signed hash check (packets will be encrypted if this is set to true, you will need custom packetconverter to decrypt them)
    bool skipVerifySignedHash = false;

    public static List<WoWConnection> g_Lists = new List<WoWConnection>();
    public static BinaryWriter g_PacketOutput = (BinaryWriter) null;
    public static int g_ConnectionID = 0;
    public static uint g_Serial = 0;
    public static ushort g_NewPort = 0;
    public static uint g_NewIP = 0;
    public static int g_NextInternalConnectionID = 0;
    public static byte[] g_EncryptSeed = new byte[16]
    {
      (byte) 144,
      (byte) 156,
      (byte) 208,
      (byte) 80,
      (byte) 90,
      (byte) 44,
      (byte) 20,
      (byte) 221,
      (byte) 92,
      (byte) 44,
      (byte) 192,
      (byte) 100,
      (byte) 20,
      (byte) 243,
      (byte) 254,
      (byte) 201
    };
    public static byte[] g_EncryptPublicExponent = new byte[4]
    {
      (byte) 1,
      (byte) 0,
      (byte) 1,
      (byte) 0
    };
    public static byte[] g_EncryptPublicModulus = new byte[256]
    {
      (byte) 113,
      (byte) 253,
      (byte) 250,
      (byte) 96,
      (byte) 20,
      (byte) 13,
      (byte) 242,
      (byte) 5,
      (byte) 63,
      (byte) 230,
      (byte) 35,
      (byte) 242,
      (byte) 216,
      (byte) 182,
      (byte) 156,
      (byte) 28,
      (byte) 9,
      (byte) 232,
      (byte) 175,
      (byte) 234,
      (byte) 51,
      (byte) 118,
      (byte) 240,
      (byte) 130,
      (byte) 252,
      (byte) 240,
      (byte) 24,
      (byte) 213,
      (byte) 89,
      (byte) 168,
      (byte) 106,
      (byte) 69,
      (byte) 152,
      (byte) 232,
      (byte) 46,
      (byte) 196,
      (byte) 145,
      (byte) 36,
      (byte) 197,
      (byte) 218,
      (byte) 188,
      (byte) 238,
      (byte) 79,
      (byte) 151,
      (byte) 145,
      (byte) 97,
      (byte) 200,
      (byte) 219,
      (byte) 190,
      (byte) 94,
      (byte) 131,
      (byte) 196,
      (byte) 81,
      (byte) 64,
      (byte) 83,
      (byte) 50,
      (byte) 131,
      (byte) 249,
      (byte) 59,
      (byte) 22,
      (byte) 18,
      (byte) 17,
      (byte) 198,
      (byte) 220,
      (byte) 169,
      (byte) 229,
      (byte) 2,
      (byte) 148,
      (byte) 226,
      (byte) 144,
      (byte) 84,
      (byte) 120,
      (byte) 246,
      (byte) 30,
      (byte) 148,
      (byte) 240,
      (byte) 57,
      (byte) 80,
      (byte) 34,
      (byte) 31,
      (byte) 199,
      (byte) 88,
      (byte) 182,
      (byte) 111,
      (byte) 226,
      (byte) 5,
      (byte) 89,
      (byte) 134,
      (byte) 131,
      (byte) 76,
      (byte) 149,
      (byte) 166,
      (byte) 230,
      (byte) 168,
      (byte) 169,
      (byte) 68,
      (byte) 182,
      (byte) 93,
      (byte) 206,
      (byte) 129,
      (byte) 235,
      (byte) 212,
      (byte) 8,
      (byte) 34,
      (byte) 70,
      (byte) 46,
      (byte) 219,
      (byte) 94,
      (byte) 97,
      (byte) 251,
      (byte) 17,
      (byte) 8,
      (byte) 160,
      (byte) 146,
      (byte) 87,
      (byte) 55,
      (byte) 197,
      (byte) 219,
      (byte) 200,
      (byte) 153,
      (byte) 177,
      (byte) 239,
      (byte) 249,
      (byte) 11,
      (byte) 100,
      (byte) 183,
      (byte) 237,
      (byte) 154,
      (byte) 147,
      (byte) 18,
      (byte) 237,
      (byte) 155,
      (byte) 110,
      (byte) 143,
      (byte) 105,
      (byte) 229,
      (byte) 18,
      (byte) 98,
      (byte) 71,
      (byte) 178,
      (byte) 194,
      (byte) 92,
      (byte) 87,
      (byte) 138,
      (byte) 117,
      (byte) 207,
      (byte) 241,
      (byte) 210,
      (byte) 94,
      (byte) 182,
      (byte) 147,
      (byte) 147,
      (byte) 66,
      (byte) 78,
      (byte) 76,
      (byte) 95,
      (byte) 71,
      (byte) 44,
      (byte) 22,
      (byte) 168,
      (byte) 89,
      (byte) 128,
      (byte) 181,
      (byte) 57,
      (byte) 51,
      (byte) 201,
      (byte) 252,
      (byte) 174,
      (byte) 24,
      (byte) 6,
      (byte) 46,
      (byte) 7,
      (byte) 219,
      (byte) 183,
      (byte) 154,
      (byte) 81,
      (byte) 161,
      (byte) 19,
      (byte) 118,
      (byte) 89,
      (byte) 120,
      (byte) 243,
      (byte) 29,
      (byte) 230,
      (byte) 171,
      (byte) 226,
      (byte) 2,
      (byte) 72,
      (byte) 216,
      (byte) 94,
      (byte) 9,
      (byte) 91,
      (byte) 48,
      (byte) 111,
      (byte) 117,
      (byte) 23,
      (byte) 69,
      (byte) 225,
      (byte) 34,
      (byte) 210,
      (byte) 73,
      (byte) 153,
      (byte) 10,
      (byte) 30,
      (byte) 106,
      (byte) 85,
      (byte) 79,
      (byte) 109,
      (byte) 140,
      (byte) 223,
      (byte) 129,
      (byte) 206,
      (byte) 6,
      (byte) 38,
      byte.MaxValue,
      (byte) 83,
      (byte) 153,
      (byte) 83,
      (byte) 54,
      (byte) 240,
      byte.MaxValue,
      (byte) 63,
      (byte) 67,
      (byte) 217,
      (byte) 30,
      (byte) 146,
      (byte) 55,
      (byte) 248,
      (byte) 16,
      (byte) 149,
      (byte) 245,
      (byte) 72,
      (byte) 197,
      (byte) 250,
      (byte) 5,
      (byte) 104,
      (byte) 54,
      (byte) 10,
      (byte) 134,
      (byte) 26,
      (byte) 23,
      (byte) 138,
      (byte) 185,
      (byte) 180,
      (byte) 155,
      (byte) 178,
      (byte) 75,
      (byte) 127,
      (byte) 240,
      (byte) 85,
      (byte) 247,
      (byte) 140,
      (byte) 84,
      (byte) 11,
      (byte) 42,
      (byte) 226
    };
    private static RSAParameters g_RSAPublicKey = new RSAParameters()
    {
      Modulus = WoWConnection.g_EncryptPublicModulus,
      Exponent = WoWConnection.g_EncryptPublicExponent
    };
    public static Mutex m_Lock = new Mutex();
    public static IntPtr netClientPtr = IntPtr.Zero;
    public static WoWConnection suspendedConnection = (WoWConnection) null;
    private byte[] m_EncryptSeed = new byte[16];
    private byte[] m_DecryptSeed = new byte[16];
    private byte[] m_Seed = new byte[16];
    private byte[] m_RSAKeySignature = new byte[256];
    private byte[] m_AESKey = new byte[16];
    private byte[] m_AESKey2 = new byte[16];
    private byte m_EncryptBit = 1;
    public string m_ClientAddr;
    public ushort m_ClientPort;
    public string m_ServerAddr;
    public ushort m_ServerPort;
    public MemoryStream m_RecvByteBuffer;
    public MemoryStream m_SendByteBuffer;
    public BinaryReader m_RecvReader;
    public long m_RecvPosition;
    public BinaryReader m_SendReader;
    public long m_SendPosition;
    public TcpReconstruction m_TcpReconstruction;
    private byte m_DosZeroBits;
    private WoWPacket m_CurrentSendPacket;
    private WoWPacket m_CurrentRecvPacket;
    public bool m_EncryptionEnabled;
    public bool m_IsInstanceSocket;
    public bool m_ServerToClientInit;
    public bool m_ClientToServerInit;
    public uint m_RecvPacketCount;
    public uint m_SendPacketCount;
    public int m_ConnectionID;
    public int m_InternalConnectionID;
    public ZStreamMem zstream;

    [DllImport("WoWSniffDecompressor.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void InitDecompressStream(int p_ConnectionIdx);

    [DllImport("WoWSniffDecompressor.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SetDictionary(
      int p_ConnectionIdx,
      IntPtr p_DictionaryData,
      int p_DictionarySize);

    [DllImport("WoWSniffDecompressor.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Decompress(
      int p_ConnectionIdx,
      IntPtr p_CompressedData,
      int p_CompressedSize,
      IntPtr p_UncompressedData,
      int p_UncompressedSize);

    public static int GetCurrentTimeStamp()
    {
      return (int) DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
    }

    public WoWConnection(
      string p_ClientAddr,
      ushort p_ClientPort,
      string p_ServerAddr,
      ushort p_ServerPort)
    {
      Console.WriteLine("New WoW connection detected! {0} to {1}", (object) (p_ClientAddr + ":" + p_ClientPort.ToString()), (object) (p_ServerAddr + ":" + p_ServerPort.ToString()));
      this.m_ClientAddr = p_ClientAddr;
      this.m_ClientPort = p_ClientPort;
      this.m_ServerAddr = p_ServerAddr;
      this.m_ServerPort = p_ServerPort;
      this.m_RecvByteBuffer = new MemoryStream();
      this.m_SendByteBuffer = new MemoryStream();
      this.m_RecvReader = new BinaryReader((Stream) this.m_RecvByteBuffer);
      this.m_SendReader = new BinaryReader((Stream) this.m_SendByteBuffer);
      this.m_ConnectionID = WoWConnection.g_NextInternalConnectionID;
      this.m_InternalConnectionID = WoWConnection.g_NextInternalConnectionID;
      WoWConnection.g_NextInternalConnectionID = 0;
      WoWConnection.InitDecompressStream(this.m_ConnectionID);
      WoWConnection.g_Lists.Add(this);
      this.m_TcpReconstruction = new TcpReconstruction(this.m_RecvByteBuffer, this.m_SendByteBuffer);
      this.m_RecvPosition = 0L;
      this.m_SendPosition = 0L;
    }

    public static BinaryReader BuildReaderFromStream(MemoryStream p_Stream)
    {
      MemoryStream memoryStream = new MemoryStream();
      p_Stream.WriteTo((Stream) memoryStream);
      return new BinaryReader((Stream) memoryStream)
      {
        BaseStream = {
          Position = 0
        }
      };
    }

    public long GetRemainingSendBytes()
    {
      return this.m_SendReader.BaseStream.Length - this.m_SendPosition;
    }

    public long GetRemainingRecvBytes()
    {
      return this.m_RecvReader.BaseStream.Length - this.m_RecvPosition;
    }

    public byte[] ReadRemainingRecvBytes(int p_Count)
    {
      this.m_RecvReader.BaseStream.Position = this.m_RecvPosition;
      byte[] numArray = this.m_RecvReader.ReadBytes(p_Count);
      this.m_RecvReader.BaseStream.Position = this.m_RecvReader.BaseStream.Length;
      this.m_RecvPosition += (long) p_Count;
      return numArray;
    }

    public byte[] ReadRemainingSendBytes(int p_Count)
    {
      this.m_SendReader.BaseStream.Position = this.m_SendPosition;
      byte[] numArray = this.m_SendReader.ReadBytes(p_Count);
      this.m_SendReader.BaseStream.Position = this.m_SendReader.BaseStream.Length;
      this.m_SendPosition += (long) p_Count;
      return numArray;
    }

    public void UpdateSendBuffer()
    {
      if (!this.m_ClientToServerInit)
      {
        if (this.GetRemainingSendBytes() < 53L)
          return;
        this.ReadRemainingSendBytes(53);
        this.m_ClientToServerInit = true;
      }
      while (true)
      {
        if (this.m_CurrentSendPacket == null && this.GetRemainingSendBytes() >= 16L)
        {
          BinaryReader binaryReader = WoWConnection.BuildReaderFromStream(new MemoryStream(this.ReadRemainingSendBytes(16)));
          int p_PacketSize = binaryReader.ReadInt32();
          byte[] numArray = binaryReader.ReadBytes(12);
          this.m_CurrentSendPacket = new WoWPacket(p_PacketSize, (ushort) 0);
          this.m_CurrentSendPacket.m_PacketType = 1196641603;
          this.m_CurrentSendPacket.m_NonSecretPayload = numArray;
        }
        if (this.m_CurrentSendPacket != null && this.GetRemainingSendBytes() >= (long) this.m_CurrentSendPacket.m_PacketSize)
        {
          byte[] buffer = this.ReadRemainingSendBytes(this.m_CurrentSendPacket.m_PacketSize);
          int packetSize = this.m_CurrentSendPacket.m_PacketSize;
          try
          {
            if (this.m_EncryptionEnabled)
            {
              byte[] iv = WoWConnection.Combine(BitConverter.GetBytes(this.m_SendPacketCount), new byte[8]
              {
                (byte) 0,
                (byte) 0,
                (byte) 0,
                (byte) 0,
                (byte) 67,
                (byte) 76,
                (byte) 78,
                (byte) 84
              });
              GcmBlockCipher gcmBlockCipher = new GcmBlockCipher((IBlockCipher) new AesEngine());
              ParametersWithIV parametersWithIv = new ParametersWithIV((ICipherParameters) new KeyParameter(this.m_AESKey), iv);
              gcmBlockCipher.Init(true, (ICipherParameters) parametersWithIv);
              byte[] input = WoWConnection.Combine(buffer);
              byte[] output = new byte[gcmBlockCipher.GetOutputSize(this.m_CurrentSendPacket.m_PacketSize)];
              int outOff = gcmBlockCipher.ProcessBytes(input, 0, this.m_CurrentSendPacket.m_PacketSize, output, 0);
              gcmBlockCipher.DoFinal(output, outOff);
              buffer = output;
            }
          }
          catch (Exception ex)
          {
            Console.WriteLine(ex.Message);
          }
          finally
          {
            ++this.m_SendPacketCount;
          }
          BinaryReader binaryReader = WoWConnection.BuildReaderFromStream(new MemoryStream(buffer));
          this.m_CurrentSendPacket.m_PacketID = binaryReader.ReadUInt16();
          this.m_CurrentSendPacket.m_Buffer = new BinaryReader((Stream) new MemoryStream(binaryReader.ReadBytes(packetSize - 2)));
          this.m_CurrentSendPacket.m_PacketSize = packetSize - 2;
          this.HandleWoWPacket(this.m_CurrentSendPacket, "");
          this.m_CurrentSendPacket = (WoWPacket) null;
        }
        else
          break;
      }
    }

    public void UpdateRecvBuffer()
    {
      if (!this.m_ServerToClientInit)
      {
        if (this.GetRemainingRecvBytes() < 53L)
          return;
        this.ReadRemainingRecvBytes(53);
        this.m_ServerToClientInit = true;
      }
      if (!this.m_ServerToClientInit)
        return;
      while (true)
      {
        if (this.m_CurrentRecvPacket == null && this.GetRemainingRecvBytes() >= 16L)
        {
          BinaryReader binaryReader = WoWConnection.BuildReaderFromStream(new MemoryStream(this.ReadRemainingRecvBytes(16)));
          int p_PacketSize = binaryReader.ReadInt32();
          byte[] numArray = binaryReader.ReadBytes(12);
          this.m_CurrentRecvPacket = new WoWPacket(p_PacketSize, (ushort) 0);
          this.m_CurrentRecvPacket.m_PacketType = 1196641619;
          this.m_CurrentRecvPacket.m_NonSecretPayload = numArray;
        }
        if (this.m_CurrentRecvPacket != null && this.GetRemainingRecvBytes() >= (long) this.m_CurrentRecvPacket.m_PacketSize)
        {
          if (this.m_CurrentRecvPacket.m_PacketSize >= 0)
          {
            byte[] buffer = this.ReadRemainingRecvBytes(this.m_CurrentRecvPacket.m_PacketSize);
            int count = this.m_CurrentRecvPacket.m_PacketSize - 2;
            try
            {
              if (this.m_EncryptionEnabled)
              {
                byte[] iv = WoWConnection.Combine(BitConverter.GetBytes(this.m_RecvPacketCount), new byte[8]
                {
                  (byte) 0,
                  (byte) 0,
                  (byte) 0,
                  (byte) 0,
                  (byte) 83,
                  (byte) 82,
                  (byte) 86,
                  (byte) 82
                });
                GcmBlockCipher gcmBlockCipher = new GcmBlockCipher((IBlockCipher) new AesEngine());
                gcmBlockCipher.Init(true, (ICipherParameters) new ParametersWithIV((ICipherParameters) new KeyParameter(this.m_AESKey), iv));
                byte[] input = buffer;
                byte[] output = new byte[gcmBlockCipher.GetOutputSize(input.Length)];
                int outOff = gcmBlockCipher.ProcessBytes(input, 0, input.Length, output, 0);
                gcmBlockCipher.DoFinal(output, outOff);
                buffer = output;
              }
            }
            catch (Exception ex)
            {
              Console.WriteLine(ex.Message);
            }
            finally
            {
              ++this.m_RecvPacketCount;
            }
            BinaryReader binaryReader = WoWConnection.BuildReaderFromStream(new MemoryStream(buffer));
            this.m_CurrentRecvPacket.m_PacketID = binaryReader.ReadUInt16();
            this.m_CurrentRecvPacket.m_Buffer = new BinaryReader((Stream) new MemoryStream(binaryReader.ReadBytes(count)));
            this.m_CurrentRecvPacket.m_PacketSize = count;
            if (this.m_CurrentRecvPacket.m_PacketSize < 0 || this.m_CurrentRecvPacket.m_PacketSize > (int) ushort.MaxValue)
              Console.WriteLine("ERROR: possible invalid recv packet(0x{0:x}) size: {1}; NOTE: if this happens on login its fine (hotfix packets are huge)", (object) this.m_CurrentRecvPacket.m_PacketID, (object) this.m_CurrentRecvPacket.m_PacketSize);
            this.HandleWoWPacket(this.m_CurrentRecvPacket, "");
            this.m_CurrentRecvPacket = (WoWPacket) null;
          }
          else
            goto label_10;
        }
        else
          break;
      }
      return;
label_10:
      Console.WriteLine("2 m_CurrentRecvPacket.m_PacketSize < 0 {0}", (object) this.m_CurrentRecvPacket.m_PacketSize);
    }

    public static byte[] Combine(params byte[][] arrays)
    {
      byte[] numArray = new byte[((IEnumerable<byte[]>) arrays).Sum<byte[]>((Func<byte[], int>) (a => a.Length))];
      int dstOffset = 0;
      foreach (byte[] array in arrays)
      {
        Buffer.BlockCopy((Array) array, 0, (Array) numArray, dstOffset, array.Length);
        dstOffset += array.Length;
      }
      return numArray;
    }

    public void LoadDictionaryFromClient(int connIdx)
    {
      this.zstream = new ZStreamMem(WoWConnection.netClientPtr, connIdx);
      this.zstream.InitInflateState();
      byte[] dictionary = this.zstream.GetDictionary();
      if (dictionary == null)
        return;
      IntPtr num = Marshal.AllocHGlobal(dictionary.Length);
      Marshal.Copy(dictionary, 0, num, dictionary.Length);
      WoWConnection.SetDictionary(connIdx, num, 32768);
      Marshal.FreeHGlobal(num);
    }

    public void HandleWoWPacket(WoWPacket p_Packet, string prefix)
    {
      Console.WriteLine("{0}opcodeid : 0x{1:x} size {2} connIdx={3} {4}", (object) prefix, (object) (int) p_Packet.m_PacketID, (object) p_Packet.m_PacketSize, (object) this.m_ConnectionID, (object) p_Packet.m_PacketType);
      if (p_Packet.m_PacketID == (ushort) 14180)
        WoWConnection.suspendedConnection = this;
      if (p_Packet.m_PacketID == (ushort) 12363)
      {
        if (WoWConnection.suspendedConnection != null)
        {
          this.m_ConnectionID = WoWConnection.suspendedConnection.m_ConnectionID;
          --WoWConnection.g_ConnectionID;
          WoWConnection.suspendedConnection = (WoWConnection) null;
        }
        this.LoadDictionaryFromClient(this.m_ConnectionID);
      }
      if (p_Packet.m_PacketID == (ushort) 12365)
      {
        p_Packet.m_Buffer.BaseStream.Position += 256L;
        int num = (int) p_Packet.m_Buffer.ReadByte();
        WoWConnection.g_NewIP = p_Packet.m_Buffer.ReadUInt32();
        WoWConnection.g_NewPort = p_Packet.m_Buffer.ReadUInt16();
        WoWConnection.g_Serial = p_Packet.m_Buffer.ReadUInt32();
        WoWConnection.g_NextInternalConnectionID = (int) p_Packet.m_Buffer.ReadByte();
        this.zstream = new ZStreamMem(WoWConnection.netClientPtr, this.m_ConnectionID);
        this.zstream.InitInflateState();
      }
      int packetId = (int) p_Packet.m_PacketID;
      if (p_Packet.m_PacketID == (ushort) 14182)
        this.m_IsInstanceSocket = true;
      if (p_Packet.m_PacketID == (ushort) 14181)
      {
        WoWConnection.g_NewIP = 0U;
        WoWConnection.g_NewPort = (ushort) 0;
      }
      if (p_Packet.m_PacketID == (ushort) 12360)
      {
        this.m_EncryptSeed = p_Packet.m_Buffer.ReadBytes(16);
        this.m_DecryptSeed = p_Packet.m_Buffer.ReadBytes(16);
        this.m_Seed = p_Packet.m_Buffer.ReadBytes(16);
        this.m_DosZeroBits = p_Packet.m_Buffer.ReadByte();
      }
      if (p_Packet.m_PacketID == (ushort) 12361)
      {
        this.m_RSAKeySignature = p_Packet.m_Buffer.ReadBytes(256);
        this.m_EncryptBit = ((int) (Convert.ToUInt32(p_Packet.m_Buffer.ReadByte()) >> 7) & 1) != 0 ? (byte) 1 : (byte) 0;
      }
      if (p_Packet.m_PacketID == (ushort) 14183)
      {
        RemoteProcess remoteProcess = new RemoteProcess();
        if (!remoteProcess.Open((uint) Program.m_WoWPID))
        {
          Console.WriteLine("Can't open the wow process to fetch the sessionkey, abort");
          return;
        }
        WoWConnection.netClientPtr = remoteProcess.Read<IntPtr>(remoteProcess.ImageBase + NetClient.Ptr);
        int num1 = 0;
        if (WoWConnection.g_NewPort != (ushort) 0)
        {
          for (int index = 0; index < 4; ++index)
          {
            IntPtr num2 = remoteProcess.Read<IntPtr>(WoWConnection.netClientPtr + 400 + index * 8);
            Console.WriteLine("{0}", (object) remoteProcess.ReadBytes(num2 + 324, 1)[0]);
            if (num2.ToInt64() != 0L)
            {
              byte[] numArray = remoteProcess.ReadBytes(num2 + 338, 6);
              Array.Reverse((Array) numArray, 0, 2);
              ushort uint16 = BitConverter.ToUInt16(numArray, 0);
              if ((int) BitConverter.ToUInt32(numArray, 2) == (int) WoWConnection.g_NewIP && (int) uint16 == (int) WoWConnection.g_NewPort)
              {
                num1 = index;
                break;
              }
            }
          }
        }
        int num3 = 0;
        do
        {
          this.m_AESKey = remoteProcess.ReadBytes(WoWConnection.netClientPtr + NetClient.SessionKey + num1 * 49, 16);
          byte[] hash = new HMACSHA256(this.m_AESKey).ComputeHash(WoWConnection.Combine(new byte[1]
          {
            this.m_EncryptBit
          }, WoWConnection.g_EncryptSeed));



          if ((!RSAHelper.VerifySignedHash(WoWConnection.g_RSAPublicKey, hash, this.m_RSAKeySignature)) || skipVerifySignedHash)
          {
            Console.WriteLine(string.Format("VerifySignedHash NOT OK, trying again.. {0}/{1}", (object) num3, (object) 5));
            Thread.Sleep(5);
            ++num3;
            if (WoWConnection.g_NewPort != (ushort) 0)
            {
              for (int index = 0; index < 4; ++index)
              {
                IntPtr num2 = remoteProcess.Read<IntPtr>(WoWConnection.netClientPtr + 400 + index * 8);
                if (num2.ToInt64() != 0L)
                {
                  byte[] numArray = remoteProcess.ReadBytes(num2 + 338, 6);
                  Array.Reverse((Array) numArray, 0, 2);
                  ushort uint16 = BitConverter.ToUInt16(numArray, 0);
                  int uint32 = (int) BitConverter.ToUInt32(numArray, 2);
                  Console.WriteLine((int) uint16);
                  int gNewIp = (int) WoWConnection.g_NewIP;
                  if (uint32 == gNewIp && (int) uint16 == (int) WoWConnection.g_NewPort)
                  {
                    num1 = index;
                    break;
                  }
                }
              }
            }
          }
          else
            break;
        }
        while (num3 < 5);
        if (num3 >= 5)
          Helper.WriteError(string.Format("VerifySignedHash is not ok after {0} tries.", (object) 5));
        remoteProcess.Dispose();
        this.m_EncryptionEnabled = true;
      }
      if (p_Packet.m_PacketID == (ushort) 12370)
      {
        uint num1 = p_Packet.m_Buffer.ReadUInt32();
        uint num2 = p_Packet.m_Buffer.ReadUInt32();
        uint num3 = p_Packet.m_Buffer.ReadUInt32();
        byte[] numArray1 = p_Packet.m_Buffer.ReadBytes(p_Packet.m_PacketSize - (int) p_Packet.m_Buffer.BaseStream.Position);
        byte[] numArray2 = new byte[(int) num1];
        if ((int) Adler.Adler32(2552748273U, numArray1, 0, numArray1.Length) != (int) num3)
          Helper.WriteError(string.Format("CompressedAdler NOT OK for connIdx {0}!!!", (object) this.m_ConnectionID));
        try
        {
          IntPtr num4 = Marshal.AllocHGlobal((int) num1);
          IntPtr num5 = Marshal.AllocHGlobal(numArray1.Length);
          Marshal.Copy(numArray1, 0, num5, numArray1.Length);
          WoWConnection.Decompress(this.m_ConnectionID, num5, numArray1.Length, num4, (int) num1);
          Marshal.Copy(num4, numArray2, 0, (int) num1);
          Marshal.FreeHGlobal(num5);
          Marshal.FreeHGlobal(num4);
        }
        catch (Exception ex)
        {
          Helper.WriteError("HandleWoWPacket: Exception while decompressing SMSG_COMPRESSED_PACKET data");
          return;
        }
        if ((int) Adler.Adler32(2552748273U, numArray2, 0, numArray2.Length) != (int) num2)
          Helper.WriteError("UncompressedAdler NOT OK !!!");
        BinaryReader binaryReader = new BinaryReader((Stream) new MemoryStream(numArray2));
        WoWPacket p_Packet1 = new WoWPacket((int) num1 - 2, binaryReader.ReadUInt16())
        {
          m_PacketType = 1196641619
        };
        p_Packet1.m_Buffer = new BinaryReader((Stream) new MemoryStream(binaryReader.ReadBytes(p_Packet1.m_PacketSize)));
        this.HandleWoWPacket(p_Packet1, "    ");
      }
      else if (p_Packet.m_PacketID == (ushort) 12369)
      {
        while (p_Packet.m_Buffer.BaseStream.Position != p_Packet.m_Buffer.BaseStream.Length)
        {
          WoWPacket p_Packet1 = new WoWPacket()
          {
            m_PacketSize = (int) p_Packet.m_Buffer.ReadUInt16(),
            m_PacketID = p_Packet.m_Buffer.ReadUInt16(),
            m_PacketType = 1196641619
          };
          p_Packet1.m_Buffer = new BinaryReader((Stream) new MemoryStream(p_Packet.m_Buffer.ReadBytes(p_Packet1.m_PacketSize)));
          this.HandleWoWPacket(p_Packet1, "    ");
        }
      }
      else
      {
        p_Packet.m_Buffer.BaseStream.Position = 0L;
        byte[] numArray = p_Packet.m_Buffer.ReadBytes((int) p_Packet.m_Buffer.BaseStream.Length);
        BinaryWriter binaryWriter = new BinaryWriter((Stream) new MemoryStream());
        binaryWriter.Write((uint) p_Packet.m_PacketType);
        binaryWriter.Write((uint) this.m_ConnectionID);
        binaryWriter.Write((uint) Environment.TickCount);
        binaryWriter.Write(0U);
        binaryWriter.Write((uint) (p_Packet.m_PacketSize + 4));
        binaryWriter.Write((uint) p_Packet.m_PacketID);
        for (int index = 0; index < numArray.Length; ++index)
          binaryWriter.Write(numArray[index]);
        binaryWriter.BaseStream.Position = 0L;
        byte[] buffer = new byte[binaryWriter.BaseStream.Length];
        binaryWriter.BaseStream.Read(buffer, 0, buffer.Length);
        WoWConnection.g_PacketOutput.Write(buffer);
        WoWConnection.g_PacketOutput.Flush();
      }
    }

    public static WoWConnection GetWoWConnection(
      string p_ClientAddr,
      ushort p_ClientPort,
      string p_ServerAddr,
      ushort p_ServerPort)
    {
      foreach (WoWConnection gList in WoWConnection.g_Lists)
      {
        if (gList.m_ClientAddr == p_ClientAddr && (int) gList.m_ClientPort == (int) p_ClientPort && (gList.m_ServerAddr == p_ServerAddr && (int) gList.m_ServerPort == (int) p_ServerPort) || gList.m_ClientAddr == p_ServerAddr && (int) gList.m_ClientPort == (int) p_ServerPort && (gList.m_ServerAddr == p_ClientAddr && (int) gList.m_ServerPort == (int) p_ClientPort))
          return gList;
      }
      return (WoWConnection) null;
    }
  }
}
