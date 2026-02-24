using PinnedMemory;

namespace Poly1305.NetCore.Examples.Examples;

public static class ByteArrayExample
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

        poly.UpdateBlock(new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 }, 0, 11);
        poly.DoFinal(hash, 0);

        Console.WriteLine(BitConverter.ToString(hash.ToArray()));
    }
}
