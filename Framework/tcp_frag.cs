namespace WoWSniffer.Framework
{
  internal class tcp_frag
  {
    public ulong seq;
    public ulong len;
    public ulong data_len;
    public byte[] data;
    public tcp_frag next;
  }
}
