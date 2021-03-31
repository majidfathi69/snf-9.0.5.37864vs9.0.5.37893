using System;
using System.Collections;
using System.Globalization;
using System.Text;

namespace WoWSniffer
{
  public class BigInteger
  {
    private DigitsArray m_digits;

    public bool IsNegative
    {
      get
      {
        return this.m_digits.IsNegative;
      }
    }

    public bool IsZero
    {
      get
      {
        return this.m_digits.IsZero;
      }
    }

    public BigInteger()
    {
      this.m_digits = new DigitsArray(1, 1);
    }

    public BigInteger(long number)
    {
      for (this.m_digits = new DigitsArray(8 / DigitsArray.DataSizeOf + 1, 0); number != 0L && this.m_digits.DataUsed < this.m_digits.Count; ++this.m_digits.DataUsed)
      {
        this.m_digits[this.m_digits.DataUsed] = (uint) ((ulong) number & (ulong) DigitsArray.AllBits);
        number >>= DigitsArray.DataSizeBits;
      }
      this.m_digits.ResetDataUsed();
    }

    public BigInteger(ulong number)
    {
      for (this.m_digits = new DigitsArray(8 / DigitsArray.DataSizeOf + 1, 0); number != 0UL && this.m_digits.DataUsed < this.m_digits.Count; ++this.m_digits.DataUsed)
      {
        this.m_digits[this.m_digits.DataUsed] = (uint) (number & (ulong) DigitsArray.AllBits);
        number >>= DigitsArray.DataSizeBits;
      }
      this.m_digits.ResetDataUsed();
    }

    public BigInteger(byte[] array)
    {
      this.ConstructFrom(array, 0, array.Length);
    }

    public BigInteger(byte[] array, int length)
    {
      this.ConstructFrom(array, 0, length);
    }

    public BigInteger(byte[] array, int offset, int length)
    {
      this.ConstructFrom(array, offset, length);
    }

    public BigInteger(string digits)
    {
      this.Construct(digits, 10);
    }

    public BigInteger(string digits, int radix)
    {
      this.Construct(digits, radix);
    }

    private BigInteger(DigitsArray digits)
    {
      digits.ResetDataUsed();
      this.m_digits = digits;
    }

    private void ConstructFrom(byte[] array, int offset, int length)
    {
      if (array == null)
        throw new ArgumentNullException(nameof (array));
      if (offset > array.Length || length > array.Length)
        throw new ArgumentOutOfRangeException(nameof (offset));
      if (length > array.Length || offset + length > array.Length)
        throw new ArgumentOutOfRangeException(nameof (length));
      int num1 = length / 4;
      int num2 = length & 3;
      if (num2 != 0)
        ++num1;
      this.m_digits = new DigitsArray(num1 + 1, 0);
      int index1 = offset + length - 1;
      int index2 = 0;
      while (index1 - offset >= 3)
      {
        this.m_digits[index2] = (uint) (((int) array[index1 - 3] << 24) + ((int) array[index1 - 2] << 16) + ((int) array[index1 - 1] << 8)) + (uint) array[index1];
        ++this.m_digits.DataUsed;
        index1 -= 4;
        ++index2;
      }
      uint num3 = 0;
      for (int index3 = num2; index3 > 0; --index3)
      {
        uint num4 = (uint) array[offset + num2 - index3] << (index3 - 1) * 8;
        num3 |= num4;
      }
      this.m_digits[this.m_digits.DataUsed] = num3;
      this.m_digits.ResetDataUsed();
    }

    private void Construct(string digits, int radix)
    {
      if (digits == null)
        throw new ArgumentNullException(nameof (digits));
      BigInteger bigInteger1 = new BigInteger(1L);
      BigInteger bigInteger2 = new BigInteger();
      digits = digits.ToUpper(CultureInfo.CurrentCulture).Trim();
      int num1 = digits[0] != '-' ? 0 : 1;
      for (int index = digits.Length - 1; index >= num1; --index)
      {
        int digit = (int) digits[index];
        int num2;
        if (digit >= 48 && digit <= 57)
        {
          num2 = digit - 48;
        }
        else
        {
          if (digit < 65 || digit > 90)
            throw new ArgumentOutOfRangeException(nameof (digits));
          num2 = digit - 65 + 10;
        }
        if (num2 >= radix)
          throw new ArgumentOutOfRangeException(nameof (digits));
        bigInteger2 += bigInteger1 * (BigInteger) num2;
        bigInteger1 *= (BigInteger) radix;
      }
      if (digits[0] == '-')
        bigInteger2 = -bigInteger2;
      this.m_digits = bigInteger2.m_digits;
    }

    public static BigInteger Add(BigInteger leftSide, BigInteger rightSide)
    {
      return leftSide - rightSide;
    }

    public static BigInteger Increment(BigInteger leftSide)
    {
      return leftSide + (BigInteger) 1;
    }

    public static BigInteger Subtract(BigInteger leftSide, BigInteger rightSide)
    {
      return leftSide - rightSide;
    }

    public static BigInteger Decrement(BigInteger leftSide)
    {
      return leftSide - (BigInteger) 1;
    }

    public BigInteger Negate()
    {
      return -this;
    }

    public static BigInteger Abs(BigInteger leftSide)
    {
      if ((object) leftSide == null)
        throw new ArgumentNullException(nameof (leftSide));
      return leftSide.IsNegative ? -leftSide : leftSide;
    }

    public static BigInteger PowMod(BigInteger b, BigInteger exp, BigInteger mod)
    {
      BigInteger bigInteger = new BigInteger(1L);
      b %= mod;
      while (exp > (BigInteger) 0)
      {
        if ((exp % (BigInteger) 2).CompareTo((BigInteger) 1) == 0)
          bigInteger = bigInteger * b % mod;
        exp >>= 1;
        b = b * b % mod;
      }
      return bigInteger;
    }

    public static BigInteger Multiply(BigInteger leftSide, BigInteger rightSide)
    {
      return leftSide * rightSide;
    }

    public static BigInteger Divide(BigInteger leftSide, BigInteger rightSide)
    {
      return leftSide / rightSide;
    }

    private static void Divide(
      BigInteger leftSide,
      BigInteger rightSide,
      out BigInteger quotient,
      out BigInteger remainder)
    {
      if (leftSide.IsZero)
      {
        quotient = new BigInteger();
        remainder = new BigInteger();
      }
      else if (rightSide.m_digits.DataUsed == 1)
        BigInteger.SingleDivide(leftSide, rightSide, out quotient, out remainder);
      else
        BigInteger.MultiDivide(leftSide, rightSide, out quotient, out remainder);
    }

    private static void MultiDivide(
      BigInteger leftSide,
      BigInteger rightSide,
      out BigInteger quotient,
      out BigInteger remainder)
    {
      if (rightSide.IsZero)
        throw new DivideByZeroException();
      uint digit1 = rightSide.m_digits[rightSide.m_digits.DataUsed - 1];
      int shiftCount = 0;
      for (uint hiBitSet = DigitsArray.HiBitSet; hiBitSet != 0U && ((int) digit1 & (int) hiBitSet) == 0; hiBitSet >>= 1)
        ++shiftCount;
      int length1 = leftSide.m_digits.DataUsed + 1;
      uint[] numArray = new uint[length1];
      leftSide.m_digits.CopyTo(numArray, 0, leftSide.m_digits.DataUsed);
      DigitsArray.ShiftLeft(numArray, shiftCount);
      rightSide <<= shiftCount;
      ulong digit2 = (ulong) rightSide.m_digits[rightSide.m_digits.DataUsed - 1];
      ulong num1 = rightSide.m_digits.DataUsed >= 2 ? (ulong) rightSide.m_digits[rightSide.m_digits.DataUsed - 2] : 0UL;
      int num2 = rightSide.m_digits.DataUsed + 1;
      DigitsArray digits1 = new DigitsArray(num2, num2);
      uint[] copyFrom = new uint[leftSide.m_digits.Count + 1];
      int length2 = 0;
      ulong num3 = 1UL << DigitsArray.DataSizeBits;
      int num4 = length1 - rightSide.m_digits.DataUsed;
      int index1 = length1 - 1;
      while (num4 > 0)
      {
        long num5 = ((long) numArray[index1] << DigitsArray.DataSizeBits) + (long) numArray[index1 - 1];
        ulong num6 = (ulong) num5 / digit2;
        ulong num7 = (ulong) num5 % digit2;
        while (index1 >= 2 && ((long) num6 == (long) num3 || num6 * num1 > (num7 << DigitsArray.DataSizeBits) + (ulong) numArray[index1 - 2]))
        {
          --num6;
          num7 += digit2;
          if (num7 >= num3)
            break;
        }
        for (int index2 = 0; index2 < num2; ++index2)
          digits1[num2 - index2 - 1] = numArray[index1 - index2];
        BigInteger bigInteger1 = new BigInteger(digits1);
        BigInteger bigInteger2 = rightSide * (BigInteger) (long) num6;
        while (bigInteger2 > bigInteger1)
        {
          --num6;
          bigInteger2 -= rightSide;
        }
        BigInteger bigInteger3 = bigInteger1 - bigInteger2;
        for (int index2 = 0; index2 < num2; ++index2)
          numArray[index1 - index2] = bigInteger3.m_digits[rightSide.m_digits.DataUsed - index2];
        copyFrom[length2++] = (uint) num6;
        --num4;
        --index1;
      }
      Array.Reverse((Array) copyFrom, 0, length2);
      quotient = new BigInteger(new DigitsArray(copyFrom));
      int num8 = DigitsArray.ShiftRight(numArray, shiftCount);
      DigitsArray digits2 = new DigitsArray(num8, num8);
      digits2.CopyFrom(numArray, 0, 0, digits2.DataUsed);
      remainder = new BigInteger(digits2);
    }

    private static void SingleDivide(
      BigInteger leftSide,
      BigInteger rightSide,
      out BigInteger quotient,
      out BigInteger remainder)
    {
      if (rightSide.IsZero)
        throw new DivideByZeroException();
      DigitsArray digits1 = new DigitsArray(leftSide.m_digits);
      digits1.ResetDataUsed();
      int index1 = digits1.DataUsed - 1;
      ulong digit = (ulong) rightSide.m_digits[0];
      ulong num1 = (ulong) digits1[index1];
      uint[] array = new uint[leftSide.m_digits.Count];
      leftSide.m_digits.CopyTo(array, 0, array.Length);
      int used = 0;
      if (num1 >= digit)
      {
        array[used++] = (uint) (num1 / digit);
        digits1[index1] = (uint) (num1 % digit);
      }
      ulong num2;
      for (int index2 = index1 - 1; index2 >= 0; digits1[index2--] = (uint) (num2 % digit))
      {
        num2 = ((ulong) digits1[index2 + 1] << DigitsArray.DataSizeBits) + (ulong) digits1[index2];
        array[used++] = (uint) (num2 / digit);
        digits1[index2 + 1] = 0U;
      }
      remainder = new BigInteger(digits1);
      DigitsArray digits2 = new DigitsArray(used + 1, used);
      int index3 = 0;
      int index4 = digits2.DataUsed - 1;
      while (index4 >= 0)
      {
        digits2[index3] = array[index4];
        --index4;
        ++index3;
      }
      quotient = new BigInteger(digits2);
    }

    public static BigInteger Modulus(BigInteger leftSide, BigInteger rightSide)
    {
      return leftSide % rightSide;
    }

    public static BigInteger BitwiseAnd(BigInteger leftSide, BigInteger rightSide)
    {
      return leftSide & rightSide;
    }

    public static BigInteger BitwiseOr(BigInteger leftSide, BigInteger rightSide)
    {
      return leftSide | rightSide;
    }

    public static BigInteger Xor(BigInteger leftSide, BigInteger rightSide)
    {
      return leftSide ^ rightSide;
    }

    public static BigInteger OnesComplement(BigInteger leftSide)
    {
      return ~leftSide;
    }

    public static BigInteger LeftShift(BigInteger leftSide, int shiftCount)
    {
      return leftSide << shiftCount;
    }

    public static BigInteger RightShift(BigInteger leftSide, int shiftCount)
    {
      if (leftSide == (BigInteger) null)
        throw new ArgumentNullException(nameof (leftSide));
      return leftSide >> shiftCount;
    }

    public int CompareTo(BigInteger value)
    {
      return BigInteger.Compare(this, value);
    }

    public static int Compare(BigInteger leftSide, BigInteger rightSide)
    {
      if ((object) leftSide == (object) rightSide)
        return 0;
      if ((object) leftSide == null)
        throw new ArgumentNullException(nameof (leftSide));
      if ((object) rightSide == null)
        throw new ArgumentNullException(nameof (rightSide));
      if (leftSide > rightSide)
        return 1;
      return leftSide == rightSide ? 0 : -1;
    }

    public override bool Equals(object obj)
    {
      if (obj == null)
        return false;
      if ((object) this == obj)
        return true;
      BigInteger bigInteger = (BigInteger) obj;
      if (this.m_digits.DataUsed != bigInteger.m_digits.DataUsed)
        return false;
      for (int index = 0; index < this.m_digits.DataUsed; ++index)
      {
        if ((int) this.m_digits[index] != (int) bigInteger.m_digits[index])
          return false;
      }
      return true;
    }

    public override int GetHashCode()
    {
      return this.m_digits.GetHashCode();
    }

    public override string ToString()
    {
      return this.ToString(10);
    }

    public string ToString(int radix)
    {
      if (radix < 2 || radix > 36)
        throw new ArgumentOutOfRangeException(nameof (radix));
      if (this.IsZero)
        return "0";
      bool isNegative = this.IsNegative;
      BigInteger leftSide = BigInteger.Abs(this);
      BigInteger rightSide = new BigInteger((long) radix);
      ArrayList arrayList = new ArrayList();
      BigInteger quotient;
      for (; leftSide.m_digits.DataUsed > 1 || leftSide.m_digits.DataUsed == 1 && leftSide.m_digits[0] != 0U; leftSide = quotient)
      {
        BigInteger remainder;
        BigInteger.Divide(leftSide, rightSide, out quotient, out remainder);
        arrayList.Insert(0, (object) "0123456789abcdefghijklmnopqrstuvwxyz"[(int) remainder.m_digits[0]]);
      }
      string str = new string((char[]) arrayList.ToArray(typeof (char)));
      return radix == 10 & isNegative ? "-" + str : str;
    }

    public string ToHexString()
    {
      StringBuilder stringBuilder = new StringBuilder();
      stringBuilder.AppendFormat("{0:X}", (object) this.m_digits[this.m_digits.DataUsed - 1]);
      string format = "{0:X" + (2 * DigitsArray.DataSizeOf).ToString() + "}";
      for (int index = this.m_digits.DataUsed - 2; index >= 0; --index)
        stringBuilder.AppendFormat(format, (object) this.m_digits[index]);
      return stringBuilder.ToString();
    }

    public static int ToInt16(BigInteger value)
    {
      if ((object) value == null)
        throw new ArgumentNullException(nameof (value));
      return (int) short.Parse(value.ToString(), NumberStyles.Integer, (IFormatProvider) CultureInfo.CurrentCulture);
    }

    public static uint ToUInt16(BigInteger value)
    {
      if ((object) value == null)
        throw new ArgumentNullException(nameof (value));
      return (uint) ushort.Parse(value.ToString(), NumberStyles.Integer, (IFormatProvider) CultureInfo.CurrentCulture);
    }

    public static int ToInt32(BigInteger value)
    {
      if ((object) value == null)
        throw new ArgumentNullException(nameof (value));
      return int.Parse(value.ToString(), NumberStyles.Integer, (IFormatProvider) CultureInfo.CurrentCulture);
    }

    public static uint ToUInt32(BigInteger value)
    {
      if ((object) value == null)
        throw new ArgumentNullException(nameof (value));
      return uint.Parse(value.ToString(), NumberStyles.Integer, (IFormatProvider) CultureInfo.CurrentCulture);
    }

    public static long ToInt64(BigInteger value)
    {
      if ((object) value == null)
        throw new ArgumentNullException(nameof (value));
      return long.Parse(value.ToString(), NumberStyles.Integer, (IFormatProvider) CultureInfo.CurrentCulture);
    }

    public static ulong ToUInt64(BigInteger value)
    {
      if ((object) value == null)
        throw new ArgumentNullException(nameof (value));
      return ulong.Parse(value.ToString(), NumberStyles.Integer, (IFormatProvider) CultureInfo.CurrentCulture);
    }

    public static implicit operator BigInteger(long value)
    {
      return new BigInteger(value);
    }

    public static implicit operator BigInteger(ulong value)
    {
      return new BigInteger(value);
    }

    public static implicit operator BigInteger(int value)
    {
      return new BigInteger((long) value);
    }

    public static implicit operator BigInteger(uint value)
    {
      return new BigInteger((ulong) value);
    }

    public static BigInteger operator +(BigInteger leftSide, BigInteger rightSide)
    {
      DigitsArray digits = new DigitsArray(Math.Max(leftSide.m_digits.DataUsed, rightSide.m_digits.DataUsed) + 1);
      long num1 = 0;
      for (int index = 0; index < digits.Count; ++index)
      {
        long num2 = (long) leftSide.m_digits[index] + (long) rightSide.m_digits[index] + num1;
        num1 = num2 >> DigitsArray.DataSizeBits;
        digits[index] = (uint) ((ulong) num2 & (ulong) DigitsArray.AllBits);
      }
      return new BigInteger(digits);
    }

    public static BigInteger operator ++(BigInteger leftSide)
    {
      return leftSide + (BigInteger) 1;
    }

    public static BigInteger operator -(BigInteger leftSide, BigInteger rightSide)
    {
      DigitsArray digits = new DigitsArray(Math.Max(leftSide.m_digits.DataUsed, rightSide.m_digits.DataUsed) + 1);
      long num1 = 0;
      for (int index = 0; index < digits.Count; ++index)
      {
        long num2 = (long) leftSide.m_digits[index] - (long) rightSide.m_digits[index] - num1;
        digits[index] = (uint) ((ulong) num2 & (ulong) DigitsArray.AllBits);
        ++digits.DataUsed;
        num1 = num2 >= 0L ? 0L : 1L;
      }
      return new BigInteger(digits);
    }

    public static BigInteger operator --(BigInteger leftSide)
    {
      return leftSide - (BigInteger) 1;
    }

    public static BigInteger operator -(BigInteger leftSide)
    {
      if ((object) leftSide == null)
        throw new ArgumentNullException(nameof (leftSide));
      if (leftSide.IsZero)
        return new BigInteger(0L);
      DigitsArray digits = new DigitsArray(leftSide.m_digits.DataUsed + 1, leftSide.m_digits.DataUsed + 1);
      for (int index = 0; index < digits.Count; ++index)
        digits[index] = ~leftSide.m_digits[index];
      bool flag = true;
      for (int index = 0; flag && index < digits.Count; ++index)
      {
        long num = (long) digits[index] + 1L;
        digits[index] = (uint) ((ulong) num & (ulong) DigitsArray.AllBits);
        flag = num >> DigitsArray.DataSizeBits > 0L;
      }
      return new BigInteger(digits);
    }

    public static BigInteger operator *(BigInteger leftSide, BigInteger rightSide)
    {
      if ((object) leftSide == null)
        throw new ArgumentNullException(nameof (leftSide));
      if ((object) rightSide == null)
        throw new ArgumentNullException(nameof (rightSide));
      bool isNegative1 = leftSide.IsNegative;
      bool isNegative2 = rightSide.IsNegative;
      leftSide = BigInteger.Abs(leftSide);
      rightSide = BigInteger.Abs(rightSide);
      DigitsArray digits = new DigitsArray(leftSide.m_digits.DataUsed + rightSide.m_digits.DataUsed);
      digits.DataUsed = digits.Count;
      for (int index1 = 0; index1 < leftSide.m_digits.DataUsed; ++index1)
      {
        ulong num1 = 0;
        int index2 = 0;
        int index3 = index1;
        while (index2 < rightSide.m_digits.DataUsed)
        {
          ulong num2 = (ulong) leftSide.m_digits[index1] * (ulong) rightSide.m_digits[index2] + (ulong) digits[index3] + num1;
          digits[index3] = (uint) (num2 & (ulong) DigitsArray.AllBits);
          num1 = num2 >> DigitsArray.DataSizeBits;
          ++index2;
          ++index3;
        }
        if (num1 != 0UL)
          digits[index1 + rightSide.m_digits.DataUsed] = (uint) num1;
      }
      BigInteger bigInteger = new BigInteger(digits);
      return isNegative1 != isNegative2 ? -bigInteger : bigInteger;
    }

    public static BigInteger operator /(BigInteger leftSide, BigInteger rightSide)
    {
      if (leftSide == (BigInteger) null)
        throw new ArgumentNullException(nameof (leftSide));
      if (rightSide == (BigInteger) null)
        throw new ArgumentNullException(nameof (rightSide));
      if (rightSide.IsZero)
        throw new DivideByZeroException();
      bool isNegative1 = rightSide.IsNegative;
      bool isNegative2 = leftSide.IsNegative;
      leftSide = BigInteger.Abs(leftSide);
      rightSide = BigInteger.Abs(rightSide);
      if (leftSide < rightSide)
        return new BigInteger(0L);
      BigInteger quotient;
      BigInteger.Divide(leftSide, rightSide, out quotient, out BigInteger _);
      return isNegative2 != isNegative1 ? -quotient : quotient;
    }

    public static BigInteger operator %(BigInteger leftSide, BigInteger rightSide)
    {
      if (leftSide == (BigInteger) null)
        throw new ArgumentNullException(nameof (leftSide));
      if (rightSide == (BigInteger) null)
        throw new ArgumentNullException(nameof (rightSide));
      if (rightSide.IsZero)
        throw new DivideByZeroException();
      bool isNegative = leftSide.IsNegative;
      leftSide = BigInteger.Abs(leftSide);
      rightSide = BigInteger.Abs(rightSide);
      if (leftSide < rightSide)
        return leftSide;
      BigInteger remainder;
      BigInteger.Divide(leftSide, rightSide, out BigInteger _, out remainder);
      return isNegative ? -remainder : remainder;
    }

    public static BigInteger operator &(BigInteger leftSide, BigInteger rightSide)
    {
      int num = Math.Max(leftSide.m_digits.DataUsed, rightSide.m_digits.DataUsed);
      DigitsArray digits = new DigitsArray(num, num);
      for (int index = 0; index < num; ++index)
        digits[index] = leftSide.m_digits[index] & rightSide.m_digits[index];
      return new BigInteger(digits);
    }

    public static BigInteger operator |(BigInteger leftSide, BigInteger rightSide)
    {
      int num = Math.Max(leftSide.m_digits.DataUsed, rightSide.m_digits.DataUsed);
      DigitsArray digits = new DigitsArray(num, num);
      for (int index = 0; index < num; ++index)
        digits[index] = leftSide.m_digits[index] | rightSide.m_digits[index];
      return new BigInteger(digits);
    }

    public static BigInteger operator ^(BigInteger leftSide, BigInteger rightSide)
    {
      int num = Math.Max(leftSide.m_digits.DataUsed, rightSide.m_digits.DataUsed);
      DigitsArray digits = new DigitsArray(num, num);
      for (int index = 0; index < num; ++index)
        digits[index] = leftSide.m_digits[index] ^ rightSide.m_digits[index];
      return new BigInteger(digits);
    }

    public static BigInteger operator ~(BigInteger leftSide)
    {
      DigitsArray digits = new DigitsArray(leftSide.m_digits.Count);
      for (int index = 0; index < digits.Count; ++index)
        digits[index] = ~leftSide.m_digits[index];
      return new BigInteger(digits);
    }

    public static BigInteger operator <<(BigInteger leftSide, int shiftCount)
    {
      if (leftSide == (BigInteger) null)
        throw new ArgumentNullException(nameof (leftSide));
      DigitsArray digits = new DigitsArray(leftSide.m_digits);
      digits.DataUsed = digits.ShiftLeftWithoutOverflow(shiftCount);
      return new BigInteger(digits);
    }

    public static BigInteger operator >>(BigInteger leftSide, int shiftCount)
    {
      if (leftSide == (BigInteger) null)
        throw new ArgumentNullException(nameof (leftSide));
      DigitsArray digits = new DigitsArray(leftSide.m_digits);
      digits.DataUsed = digits.ShiftRight(shiftCount);
      if (leftSide.IsNegative)
      {
        for (int index = digits.Count - 1; index >= digits.DataUsed; --index)
          digits[index] = DigitsArray.AllBits;
        uint hiBitSet = DigitsArray.HiBitSet;
        for (int index1 = 0; index1 < DigitsArray.DataSizeBits && ((int) digits[digits.DataUsed - 1] & (int) hiBitSet) != (int) DigitsArray.HiBitSet; ++index1)
        {
          DigitsArray digitsArray;
          int index2;
          uint num = (digitsArray = digits)[index2 = digits.DataUsed - 1];
          digitsArray[index2] = num | hiBitSet;
          hiBitSet >>= 1;
        }
        digits.DataUsed = digits.Count;
      }
      return new BigInteger(digits);
    }

    public static bool operator ==(BigInteger leftSide, BigInteger rightSide)
    {
      if ((object) leftSide == (object) rightSide)
        return true;
      return (object) leftSide != null && (object) rightSide != null && leftSide.IsNegative == rightSide.IsNegative && leftSide.Equals((object) rightSide);
    }

    public static bool operator !=(BigInteger leftSide, BigInteger rightSide)
    {
      return !(leftSide == rightSide);
    }

    public static bool operator >(BigInteger leftSide, BigInteger rightSide)
    {
      if ((object) leftSide == null)
        throw new ArgumentNullException(nameof (leftSide));
      if ((object) rightSide == null)
        throw new ArgumentNullException(nameof (rightSide));
      if (leftSide.IsNegative != rightSide.IsNegative)
        return rightSide.IsNegative;
      if (leftSide.m_digits.DataUsed != rightSide.m_digits.DataUsed)
        return leftSide.m_digits.DataUsed > rightSide.m_digits.DataUsed;
      for (int index = leftSide.m_digits.DataUsed - 1; index >= 0; --index)
      {
        if ((int) leftSide.m_digits[index] != (int) rightSide.m_digits[index])
          return leftSide.m_digits[index] > rightSide.m_digits[index];
      }
      return false;
    }

    public static bool operator <(BigInteger leftSide, BigInteger rightSide)
    {
      if ((object) leftSide == null)
        throw new ArgumentNullException(nameof (leftSide));
      if ((object) rightSide == null)
        throw new ArgumentNullException(nameof (rightSide));
      if (leftSide.IsNegative != rightSide.IsNegative)
        return leftSide.IsNegative;
      if (leftSide.m_digits.DataUsed != rightSide.m_digits.DataUsed)
        return leftSide.m_digits.DataUsed < rightSide.m_digits.DataUsed;
      for (int index = leftSide.m_digits.DataUsed - 1; index >= 0; --index)
      {
        if ((int) leftSide.m_digits[index] != (int) rightSide.m_digits[index])
          return leftSide.m_digits[index] < rightSide.m_digits[index];
      }
      return false;
    }

    public static bool operator >=(BigInteger leftSide, BigInteger rightSide)
    {
      return BigInteger.Compare(leftSide, rightSide) >= 0;
    }

    public static bool operator <=(BigInteger leftSide, BigInteger rightSide)
    {
      return BigInteger.Compare(leftSide, rightSide) <= 0;
    }
  }
}
