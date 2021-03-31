using System.IO;

namespace WoWSniffer
{
  public class WoWPacket
  {
    public int m_PacketSize;
    public ushort m_PacketID;
    public BinaryReader m_Buffer;
    public int m_PacketType;
    public byte[] m_NonSecretPayload;

    public WoWPacket(int p_PacketSize, ushort p_PacketID)
    {
      this.m_PacketSize = p_PacketSize;
      this.m_PacketID = p_PacketID;
      this.m_Buffer = (BinaryReader) null;
      this.m_NonSecretPayload = (byte[]) null;
    }

    public WoWPacket()
    {
    }
  }
}
