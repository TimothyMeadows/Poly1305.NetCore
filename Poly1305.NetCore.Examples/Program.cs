using System;
using PinnedMemory;
using Poly1305.NetCore.Examples.Examples;

namespace Poly1305.NetCore.Examples
{
    class Program
    {
        // WARNING: It's unsafe to output pinned memory as a string, even using bitconverter however for the sake of learning this is done below.
        // DO NOT DO THIS IN YOUR APPLICATION, you should store your pinned data in it's native form so it will remain locked, and pinned in place.
        static void Main(string[] args)
        {
            ByteArrayExample.Poly();
            StringExample.Poly();
        }
    }
}
