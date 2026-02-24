using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using PinnedMemory;

namespace Poly1305.NetCore.Examples.Examples;

public static class StringExample
{
    private static readonly byte[] ExampleKey =
    {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xf1, 0xce,
        0xbf, 0xf9, 0x89, 0x7d, 0xe1, 0x45, 0x52, 0x4a
    };

    public static void Poly()
    {
        using var poly = new Poly1305(new PinnedMemory<byte>(ExampleKey, false));
        using var hash = new PinnedMemory<byte>(new byte[poly.GetLength()]);

        const string unsafeCaw = "caw caw caw";
        var cawBytes = Encoding.UTF8.GetBytes(unsafeCaw);
        using var caw = new PinnedMemory<byte>(cawBytes, false);
        poly.UpdateBlock(caw, 0, caw.Length);
        poly.DoFinal(hash, 0);
        CryptographicOperations.ZeroMemory(cawBytes);

        Console.WriteLine(BitConverter.ToString(hash.ToArray()));

        using var exampleHash2 = new PinnedMemory<byte>(new byte[poly.GetLength()]);
        using var secureCaw = new SecureString();
        foreach (var c in "caw caw caw")
        {
            secureCaw.AppendChar(c);
        }

        secureCaw.MakeReadOnly();

        var cawPointer = IntPtr.Zero;
        try
        {
            using var pinnedCaw = new PinnedMemory<char>(new char[secureCaw.Length]);
            cawPointer = Marshal.SecureStringToBSTR(secureCaw);
            for (var i = 0; i < secureCaw.Length; i++)
            {
                pinnedCaw[i] = (char)Marshal.ReadInt16(cawPointer, i * sizeof(char));
            }

            var secureBytes = Encoding.UTF8.GetBytes(pinnedCaw.ToArray());
            using var pinnedCawBytes = new PinnedMemory<byte>(secureBytes, false);
            poly.UpdateBlock(pinnedCawBytes, 0, pinnedCawBytes.Length);
            poly.DoFinal(exampleHash2, 0);
            CryptographicOperations.ZeroMemory(secureBytes);
        }
        finally
        {
            if (cawPointer != IntPtr.Zero)
            {
                Marshal.ZeroFreeBSTR(cawPointer);
            }
        }

        Console.WriteLine(BitConverter.ToString(exampleHash2.ToArray()));
    }
}
