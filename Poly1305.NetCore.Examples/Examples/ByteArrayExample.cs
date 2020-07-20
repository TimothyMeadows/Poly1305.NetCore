using System;
using System.Collections.Generic;
using System.Text;
using PinnedMemory;

namespace Poly1305.NetCore.Examples.Examples
{
    public static class ByteArrayExample
    {
        public static void Poly()
        {
            using var poly = new Poly1305(new PinnedMemory<byte>(new byte[] { 63, 61, 77, 20, 63, 61, 77 }, false));
            using var hash = new PinnedMemory<byte>(new byte[poly.GetLength()]);

            // digest.UpdateBlock(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, 0, 11); // This may be exposed without being pinned.
            poly.UpdateBlock(new PinnedMemory<byte>(new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 }, false), 0, 11);
            poly.DoFinal(hash, 0);

            Console.WriteLine(BitConverter.ToString(hash.ToArray()));
        }
    }
}
