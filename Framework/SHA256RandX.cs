using System;
using System.IO;
using System.Security.Cryptography;

namespace WoWSniffer_Legion.Framework
{
  internal class SHA256Randx
  {
    private SHA256Managed m_Sha256Hash = new SHA256Managed();
    private byte[] m_PairA = new byte[32];
    private byte[] m_PairB = new byte[32];
    private byte[] m_PairC = new byte[32];
    private uint m_SizeTaked;

    public SHA256Randx(byte[] p_SessionKeyHMAC256)
    {
      byte[] buffer1 = new byte[16];
      Buffer.BlockCopy((Array) p_SessionKeyHMAC256, 0, (Array) buffer1, 0, 16);
      this.m_Sha256Hash.Initialize();
      Buffer.BlockCopy((Array) this.m_Sha256Hash.ComputeHash(buffer1), 0, (Array) this.m_PairB, 0, 32);
      byte[] buffer2 = new byte[16];
      Buffer.BlockCopy((Array) p_SessionKeyHMAC256, 16, (Array) buffer2, 0, 16);
      this.m_Sha256Hash.Initialize();
      Buffer.BlockCopy((Array) this.m_Sha256Hash.ComputeHash(buffer2), 0, (Array) this.m_PairC, 0, 32);
      for (int index = 0; index < this.m_PairA.Length; ++index)
        this.m_PairA[index] = (byte) 0;
      this.FillUp();
    }

    public byte[] GenerateKey()
    {
      byte[] numArray = new byte[40];
      for (uint index = 0; index < 40U; ++index)
      {
        if (this.m_SizeTaked == 32U)
          this.FillUp();
        numArray[(int) index] = this.m_PairA[(int) this.m_SizeTaked];
        ++this.m_SizeTaked;
      }
      return numArray;
    }

    private void FillUp()
    {
      this.m_Sha256Hash.Initialize();
      MemoryStream memoryStream = new MemoryStream();
      memoryStream.Write(this.m_PairB, 0, this.m_PairB.Length);
      memoryStream.Write(this.m_PairA, 0, this.m_PairA.Length);
      memoryStream.Write(this.m_PairC, 0, this.m_PairC.Length);
      Buffer.BlockCopy((Array) this.m_Sha256Hash.ComputeHash(memoryStream.ToArray()), 0, (Array) this.m_PairA, 0, 32);
      this.m_SizeTaked = 0U;
    }
  }
}
