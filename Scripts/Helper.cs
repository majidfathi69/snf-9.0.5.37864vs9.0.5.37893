using System;
using System.Diagnostics;

namespace WoWSniffer
{
  public static class Helper
  {
    public static void WriteError(string format, params object[] args)
    {
      Console.ForegroundColor = ConsoleColor.Red;
      Console.WriteLine(format, args);
      Console.ForegroundColor = ConsoleColor.Gray;
      Process.GetProcessById(Program.m_WoWPID).Kill();
    }
  }
}
