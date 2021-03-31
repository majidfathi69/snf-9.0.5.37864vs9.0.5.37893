using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.IO;

namespace WoWSniffer.Framework
{
  public class TcpReconstruction
  {
    private tcp_frag[] frags = new tcp_frag[2];
    private ulong[] seq = new ulong[2];
    private long[] src_addr = new long[2];
    private uint[] src_port = new uint[2];
    private bool empty_tcp_stream = true;
    private uint[] tcp_port = new uint[2];
    private uint[] bytes_written = new uint[2];
    private bool incomplete_tcp_stream;
    private bool closed;
    private MemoryStream m_RecvStream;
    private MemoryStream m_SendStream;

    public bool IncompleteStream
    {
      get
      {
        return this.incomplete_tcp_stream;
      }
    }

    public bool EmptyStream
    {
      get
      {
        return this.empty_tcp_stream;
      }
    }

    public TcpReconstruction(MemoryStream p_RecvStream, MemoryStream p_SendStream)
    {
      this.m_RecvStream = p_RecvStream;
      this.m_SendStream = p_SendStream;
      this.reset_tcp_reassembly();
    }

    public void Close()
    {
      if (this.closed)
        return;
      this.reset_tcp_reassembly();
      this.closed = true;
    }

    ~TcpReconstruction()
    {
      this.Close();
    }

    public void ReassemblePacket(Packet p_TcpPacket)
    {
      TcpDatagram tcp = p_TcpPacket.Ethernet.IpV4.Tcp;
      ulong num1 = (ulong) (tcp.Length - tcp.HeaderLength);
      if (num1 == 0UL)
        return;
      byte[] array = tcp.Payload.ToMemoryStream().ToArray();
      long sequenceNumber = (long) tcp.SequenceNumber;
      long num2 = (long) num1;
      byte[] data = array;
      long length = (long) array.Length;
      int num3 = tcp.IsSynchronize ? 1 : 0;
      IpV4Address ipV4Address = p_TcpPacket.Ethernet.IpV4.Source;
      long net_src = (long) ipV4Address.ToValue();
      ipV4Address = p_TcpPacket.Ethernet.IpV4.Destination;
      long net_dst = (long) ipV4Address.ToValue();
      int sourcePort = (int) p_TcpPacket.Ethernet.IpV4.Transport.SourcePort;
      int destinationPort = (int) p_TcpPacket.Ethernet.IpV4.Transport.DestinationPort;
      this.reassemble_tcp((ulong) sequenceNumber, (ulong) num2, data, (ulong) length, num3 != 0, net_src, net_dst, (uint) sourcePort, (uint) destinationPort);
    }

    private void write_packet_data(int index, byte[] data)
    {
      if (data.Length == 0)
        return;
      if (index == 1)
        this.m_SendStream.Write(data, 0, data.Length);
      if (index == 0)
        this.m_RecvStream.Write(data, 0, data.Length);
      this.bytes_written[index] += (uint) data.Length;
      this.empty_tcp_stream = false;
    }

    private void reassemble_tcp(
      ulong sequence,
      ulong length,
      byte[] data,
      ulong data_length,
      bool synflag,
      long net_src,
      long net_dst,
      uint srcport,
      uint dstport)
    {
      bool flag = false;
      int index1 = -1;
      long num1 = net_src;
      for (int index2 = 0; index2 < 2; ++index2)
      {
        if (this.src_addr[index2] == num1 && (int) this.src_port[index2] == (int) srcport)
          index1 = index2;
      }
      if (index1 < 0)
      {
        for (int index2 = 0; index2 < 2; ++index2)
        {
          if (this.src_port[index2] == 0U)
          {
            this.src_addr[index2] = num1;
            this.src_port[index2] = srcport;
            index1 = index2;
            flag = true;
            break;
          }
        }
      }
      if (index1 < 0)
        throw new Exception("ERROR in reassemble_tcp: Too many addresses!");
      if (data_length < length)
        this.incomplete_tcp_stream = true;
      if (flag)
      {
        this.seq[index1] = sequence + length;
        if (synflag)
          ++this.seq[index1];
        this.write_packet_data(index1, data);
      }
      else
      {
        if (sequence < this.seq[index1])
        {
          ulong num2 = sequence + length;
          if (num2 > this.seq[index1])
          {
            ulong num3 = this.seq[index1] - sequence;
            if (data_length <= num3)
            {
              data = (byte[]) null;
              data_length = 0UL;
              this.incomplete_tcp_stream = true;
            }
            else
            {
              data_length -= num3;
              byte[] numArray = new byte[data_length];
              for (ulong index2 = 0; index2 < data_length; ++index2)
                numArray[index2] = data[checked ((ulong) unchecked ((long) index2 + (long) num3))];
              data = numArray;
            }
            sequence = this.seq[index1];
            length = num2 - this.seq[index1];
          }
        }
        if ((long) sequence == (long) this.seq[index1])
        {
          this.seq[index1] += length;
          if (synflag)
            ++this.seq[index1];
          if (data != null)
            this.write_packet_data(index1, data);
          do
            ;
          while (this.check_fragments(index1));
        }
        else
        {
          if (data_length <= 0UL || sequence <= this.seq[index1])
            return;
          this.frags[index1] = new tcp_frag()
          {
            data = data,
            seq = sequence,
            len = length,
            data_len = data_length,
            next = this.frags[index1] == null ? (tcp_frag) null : this.frags[index1]
          };
        }
      }
    }

    private bool check_fragments(int index)
    {
      tcp_frag tcpFrag1 = (tcp_frag) null;
      for (tcp_frag tcpFrag2 = this.frags[index]; tcpFrag2 != null; tcpFrag2 = tcpFrag2.next)
      {
        if ((long) tcpFrag2.seq == (long) this.seq[index])
        {
          if (tcpFrag2.data != null)
            this.write_packet_data(index, tcpFrag2.data);
          this.seq[index] += tcpFrag2.len;
          if (tcpFrag1 != null)
            tcpFrag1.next = tcpFrag2.next;
          else
            this.frags[index] = tcpFrag2.next;
          tcpFrag2.data = (byte[]) null;
          return true;
        }
        tcpFrag1 = tcpFrag2;
      }
      return false;
    }

    private void reset_tcp_reassembly()
    {
      this.empty_tcp_stream = true;
      this.incomplete_tcp_stream = false;
      for (int index = 0; index < 2; ++index)
      {
        this.seq[index] = 0UL;
        this.src_addr[index] = 0L;
        this.src_port[index] = 0U;
        this.tcp_port[index] = 0U;
        this.bytes_written[index] = 0U;
        tcp_frag next;
        for (tcp_frag tcpFrag = this.frags[index]; tcpFrag != null; tcpFrag = next)
        {
          next = tcpFrag.next;
          tcpFrag.data = (byte[]) null;
        }
        this.frags[index] = (tcp_frag) null;
      }
    }
  }
}
