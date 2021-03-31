using System;
using System.Collections.Generic;

namespace WoWSniffer
{
  internal class DigitsArray
  {
    internal static readonly uint AllBits = uint.MaxValue;
    internal static readonly uint HiBitSet = (uint) (1 << DigitsArray.DataSizeBits - 1);
    private uint[] m_data;
    private int m_dataUsed;

    internal static int DataSizeOf
    {
      get
      {
        return 4;
      }
    }

    internal static int DataSizeBits
    {
      get
      {
        return 32;
      }
    }

    internal uint this[int index]
    {
      get
      {
        if (index < this.m_dataUsed)
          return this.m_data[index];
        return this.IsNegative ? DigitsArray.AllBits : 0U;
      }
      set
      {
        this.m_data[index] = value;
      }
    }

    internal int DataUsed
    {
      get
      {
        return this.m_dataUsed;
      }
      set
      {
        this.m_dataUsed = value;
      }
    }

    internal int Count
    {
      get
      {
        return this.m_data.Length;
      }
    }

    internal bool IsZero
    {
      get
      {
        if (this.m_dataUsed == 0)
          return true;
        return this.m_dataUsed == 1 && this.m_data[0] == 0U;
      }
    }

    internal bool IsNegative
    {
      get
      {
        return ((int) this.m_data[this.m_data.Length - 1] & (int) DigitsArray.HiBitSet) == (int) DigitsArray.HiBitSet;
      }
    }

    internal DigitsArray(int size)
    {
      this.Allocate(size, 0);
    }

    internal DigitsArray(int size, int used)
    {
      this.Allocate(size, used);
    }

    internal DigitsArray(uint[] copyFrom)
    {
      this.Allocate(copyFrom.Length);
      this.CopyFrom(copyFrom, 0, 0, copyFrom.Length);
      this.ResetDataUsed();
    }

    internal DigitsArray(DigitsArray copyFrom)
    {
      this.Allocate(copyFrom.Count, copyFrom.DataUsed);
      Array.Copy((Array) copyFrom.m_data, 0, (Array) this.m_data, 0, copyFrom.Count);
    }

    public void Allocate(int size)
    {
      this.Allocate(size, 0);
    }

    public void Allocate(int size, int used)
    {
      this.m_data = new uint[size + 1];
      this.m_dataUsed = used;
    }

    internal void CopyFrom(uint[] source, int sourceOffset, int offset, int length)
    {
      Array.Copy((Array) source, sourceOffset, (Array) this.m_data, 0, length);
    }

    internal void CopyTo(uint[] array, int offset, int length)
    {
      Array.Copy((Array) this.m_data, 0, (Array) array, offset, length);
    }

    internal void ResetDataUsed()
    {
      this.m_dataUsed = this.m_data.Length;
      if (this.IsNegative)
      {
        while (this.m_dataUsed > 1 && (int) this.m_data[this.m_dataUsed - 1] == (int) DigitsArray.AllBits)
          --this.m_dataUsed;
        ++this.m_dataUsed;
      }
      else
      {
        while (this.m_dataUsed > 1 && this.m_data[this.m_dataUsed - 1] == 0U)
          --this.m_dataUsed;
        if (this.m_dataUsed != 0)
          return;
        this.m_dataUsed = 1;
      }
    }

    internal int ShiftRight(int shiftCount)
    {
      return DigitsArray.ShiftRight(this.m_data, shiftCount);
    }

    internal static int ShiftRight(uint[] buffer, int shiftCount)
    {
      int num1 = DigitsArray.DataSizeBits;
      int num2 = 0;
      int length = buffer.Length;
      while (length > 1 && buffer[length - 1] == 0U)
        --length;
      for (int index1 = shiftCount; index1 > 0; index1 -= num1)
      {
        if (index1 < num1)
        {
          num1 = index1;
          num2 = DigitsArray.DataSizeBits - num1;
        }
        ulong num3 = 0;
        for (int index2 = length - 1; index2 >= 0; --index2)
        {
          ulong num4 = (ulong) buffer[index2] >> num1 | num3;
          num3 = (ulong) buffer[index2] << num2;
          buffer[index2] = (uint) num4;
        }
      }
      while (length > 1 && buffer[length - 1] == 0U)
        --length;
      return length;
    }

    internal int ShiftLeft(int shiftCount)
    {
      return DigitsArray.ShiftLeft(this.m_data, shiftCount);
    }

    internal static int ShiftLeft(uint[] buffer, int shiftCount)
    {
      int num1 = DigitsArray.DataSizeBits;
      int length = buffer.Length;
      while (length > 1 && buffer[length - 1] == 0U)
        --length;
      for (int index1 = shiftCount; index1 > 0; index1 -= num1)
      {
        if (index1 < num1)
          num1 = index1;
        ulong num2 = 0;
        for (int index2 = 0; index2 < length; ++index2)
        {
          ulong num3 = (ulong) buffer[index2] << num1 | num2;
          buffer[index2] = (uint) (num3 & (ulong) DigitsArray.AllBits);
          num2 = num3 >> DigitsArray.DataSizeBits;
        }
        if (num2 != 0UL)
        {
          if (length + 1 > buffer.Length)
            throw new OverflowException();
          buffer[length] = (uint) num2;
          ++length;
        }
      }
      return length;
    }

    internal int ShiftLeftWithoutOverflow(int shiftCount)
    {
      List<uint> uintList = new List<uint>((IEnumerable<uint>) this.m_data);
      int num1 = DigitsArray.DataSizeBits;
      for (int index1 = shiftCount; index1 > 0; index1 -= num1)
      {
        if (index1 < num1)
          num1 = index1;
        ulong num2 = 0;
        for (int index2 = 0; index2 < uintList.Count; ++index2)
        {
          ulong num3 = (ulong) uintList[index2] << num1 | num2;
          uintList[index2] = (uint) (num3 & (ulong) DigitsArray.AllBits);
          num2 = num3 >> DigitsArray.DataSizeBits;
        }
        if (num2 != 0UL)
        {
          uintList.Add(0U);
          uintList[uintList.Count - 1] = (uint) num2;
        }
      }
      this.m_data = new uint[uintList.Count];
      uintList.CopyTo(this.m_data);
      return this.m_data.Length;
    }
  }
}
