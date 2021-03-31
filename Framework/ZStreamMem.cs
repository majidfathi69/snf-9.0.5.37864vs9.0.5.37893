using MyMemory_x64;
using Offsets;
using System;

namespace WoWSniffer
{
  public class ZStreamMem
  {
    private int _connIdx;
    private IntPtr _z_stream;
    private IntPtr _inflate_state;
    private int _whave;
    private int _wnext;
    private IntPtr _window;
    private RemoteProcess _proc;

    public ZStreamMem(IntPtr netClient, int connIdx)
    {
      this._connIdx = connIdx;
      this._proc = new RemoteProcess();
      if (!this._proc.Open((uint) Program.m_WoWPID))
        Console.WriteLine("ZStreamMem::ZStreamMem: Cannot open process.");
      else
        this._z_stream = this._proc.Read<IntPtr>(netClient + 8 * connIdx + NetClient.ZStreamPtr);
    }

    public void InitInflateState()
    {
      this._inflate_state = this._proc.Read<IntPtr>(this._z_stream + ZStream.inflate_state_ptr);
      this._whave = this._proc.Read<int>(this._inflate_state + ZStream.InflateState.whave);
      this._wnext = this._proc.Read<int>(this._inflate_state + ZStream.InflateState.wnext);
      this._window = this._proc.Read<IntPtr>(this._inflate_state + ZStream.InflateState.window);
    }

    public byte[] GetDictionary()
    {
      if ((long) this._z_stream == 0L)
      {
        Console.WriteLine("_z_stream is null, not reading dictionary.");
        return (byte[]) null;
      }
      byte[] numArray1 = new byte[32768];
      if (this._whave != 0)
      {
        byte[] numArray2 = this._proc.ReadBytes(this._window + this._wnext, this._whave - this._wnext);
        byte[] numArray3 = this._proc.ReadBytes(this._window, this._wnext);
        byte[] numArray4 = numArray1;
        int length = this._whave - this._wnext;
        Array.Copy((Array) numArray2, (Array) numArray4, length);
        Array.Copy((Array) numArray3, 0, (Array) numArray1, this._whave - this._wnext, this._wnext);
      }
      this._proc.Dispose();
      return numArray1;
    }
  }
}
