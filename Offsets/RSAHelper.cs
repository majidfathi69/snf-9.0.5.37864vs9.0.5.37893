using System;
using System.Security.Cryptography;

namespace WoWSniffer
{
  internal class RSAHelper
  {
    public static bool MakePKCS1SignatureBlock(
      byte[] hash,
      int hashSize,
      byte[] id,
      int idSize,
      byte[] signature,
      int signatureSize)
    {
      int num1 = 3 + idSize + hashSize;
      if (num1 > signatureSize)
        return false;
      int num2 = signatureSize - num1;
      int num3 = 0;
      for (int index = 0; index < hashSize; ++index)
        signature[num3++] = hash[hashSize - index - 1];
      for (int index = 0; index < idSize; ++index)
        signature[num3++] = id[idSize - index - 1];
      byte[] numArray1 = signature;
      int index1 = num3;
      int num4 = index1 + 1;
      numArray1[index1] = (byte) 0;
      for (int index2 = 0; index2 < num2; ++index2)
        signature[num4++] = byte.MaxValue;
      byte[] numArray2 = signature;
      int index3 = num4;
      int num5 = index3 + 1;
      numArray2[index3] = (byte) 1;
      byte[] numArray3 = signature;
      int index4 = num5;
      int num6 = index4 + 1;
      numArray3[index4] = (byte) 0;
      return num6 == signatureSize;
    }

    public static bool VerifySignedHash(RSAParameters key, byte[] hash, byte[] signature)
    {
      byte[] array1 = new byte[key.Modulus.Length];
      byte[] array2 = new byte[key.Exponent.Length];
      byte[] array3 = new byte[signature.Length];
      Array.Copy((Array) key.Modulus, (Array) array1, key.Modulus.Length);
      Array.Copy((Array) key.Exponent, (Array) array2, key.Exponent.Length);
      Array.Copy((Array) signature, (Array) array3, signature.Length);
      Array.Reverse((Array) array1);
      Array.Reverse((Array) array2);
      Array.Reverse((Array) array3);
      BigInteger mod = new BigInteger(array1);
      BigInteger exp = new BigInteger(array2);
      BigInteger bigInteger = BigInteger.PowMod(new BigInteger(array3), exp, mod);
      byte[] signature1 = new byte[key.Modulus.Length];
      byte[] id = new byte[19]
      {
        (byte) 48,
        (byte) 49,
        (byte) 48,
        (byte) 13,
        (byte) 6,
        (byte) 9,
        (byte) 96,
        (byte) 134,
        (byte) 72,
        (byte) 1,
        (byte) 101,
        (byte) 3,
        (byte) 4,
        (byte) 2,
        (byte) 1,
        (byte) 5,
        (byte) 0,
        (byte) 4,
        (byte) 32
      };
      if (!RSAHelper.MakePKCS1SignatureBlock(hash, hash.Length, id, id.Length, signature1, key.Modulus.Length))
        return false;
      byte[] array4 = new byte[signature1.Length];
      Array.Copy((Array) signature1, (Array) array4, signature1.Length);
      Array.Reverse((Array) array4);
      return new BigInteger(array4).CompareTo(bigInteger) == 0;
    }
  }
}
