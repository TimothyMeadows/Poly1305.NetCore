using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using PinnedMemory;

namespace Poly1305.NetCore.Examples.Examples
{
    public static class StringExample
    {
        // Strings are very unsafe to store passwords, or keys in. This is because strings in .NET will always be subject to garbage collection
        // which means they can always be dumped out of memory onto disk through various methods, and exploits. However, especially when dealing
        // with website logins through forms. It's almost impossible to avoid the risk completely. Below are some examples of best dealing with 
        // these conditions. Ultimately however, if you can record your secure input directly in byte, char, or SecureString you will always be better off.
        public static void Poly()
        {
            using var poly = new Poly1305(new PinnedMemory<byte>(new byte[] { 63, 61, 77, 20, 63, 61, 77 }, false));
            using var hash = new PinnedMemory<byte>(new byte[poly.GetLength()]);

            var unsafeCaw = "caw caw caw"; // this is unsafe because string's can't be pinned and are subject to garbage collection, and being written to disk (pagefile).
            var caw = new PinnedMemory<byte>(Encoding.UTF8.GetBytes(unsafeCaw), false); // this is now safe but ONLY the variable caw, unsafeCaw is STILL exposed.
            unsafeCaw = string.Empty; // unsafeCaw COULD STILL exposed even tho we set it to empty because this depends on garbage collection getting around to clearing it.
            poly.UpdateBlock(caw, 0, caw.Length);
            poly.DoFinal(hash, 0);

            Console.WriteLine(BitConverter.ToString(hash.ToArray()));

            // This is a more uncommon but should be safer example of how to use strings with SecureString for input.
            using var exampleHash2 = new PinnedMemory<byte>(new byte[poly.GetLength()]);

            var secureCaw = new SecureString();
            secureCaw.AppendChar('c');
            secureCaw.AppendChar('a');
            secureCaw.AppendChar('w');
            secureCaw.AppendChar(' ');
            secureCaw.AppendChar('c');
            secureCaw.AppendChar('a');
            secureCaw.AppendChar('w');
            secureCaw.AppendChar(' ');
            secureCaw.AppendChar('c');
            secureCaw.AppendChar('a');
            secureCaw.AppendChar('w');
            secureCaw.MakeReadOnly();

            using var pinnedCaw = new PinnedMemory<char>(new char[secureCaw.Length]);
            var cawPointer = Marshal.SecureStringToBSTR(secureCaw);
            for (var i = 0; i <= secureCaw.Length - 1; i++)
            {
                var c = (char)Marshal.ReadByte(cawPointer, i * 2);
                pinnedCaw[i] = c;
            }

            using var pinnedCawBytes = new PinnedMemory<byte>(Encoding.UTF8.GetBytes(pinnedCaw.ToArray()), false);
            poly.UpdateBlock(pinnedCawBytes, 0, secureCaw.Length);
            poly.DoFinal(exampleHash2, 0);
            Console.WriteLine(BitConverter.ToString(exampleHash2.ToArray()));
        }
    }
}
