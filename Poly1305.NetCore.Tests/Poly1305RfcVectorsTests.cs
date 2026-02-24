using System.Text;
using PinnedMemory;

namespace Poly1305.NetCore.Tests;

public class Poly1305RfcVectorsTests
{
    [Fact]
    public void ComputesExpectedTagForRfc8439Vectors()
    {
        foreach (var vector in GetRfc8439Vectors())
        {
            var actualTag = ComputeTag(HexToBytes(vector.KeyHex), vector.Message, chunkSize: vector.Message.Length == 0 ? 1 : vector.Message.Length);
            var actualTagHex = Convert.ToHexString(actualTag).ToLowerInvariant();

            Assert.True(actualTagHex == vector.ExpectedTagHex,
                $"Vector {vector.Name} failed. Expected {vector.ExpectedTagHex}, got {actualTagHex}.");
        }
    }

    [Fact]
    public void ComputesExpectedTagForRfc8439VectorsWithStreamingUpdates()
    {
        foreach (var vector in GetRfc8439Vectors())
        {
            var actualTag = ComputeTag(HexToBytes(vector.KeyHex), vector.Message, chunkSize: 3);
            var actualTagHex = Convert.ToHexString(actualTag).ToLowerInvariant();

            Assert.True(actualTagHex == vector.ExpectedTagHex,
                $"Vector {vector.Name} failed. Expected {vector.ExpectedTagHex}, got {actualTagHex}.");
        }
    }

    private static IReadOnlyList<(string Name, string KeyHex, byte[] Message, string ExpectedTagHex)> GetRfc8439Vectors() =>
    [
        (
            "RFC8439-2.5.2-Cryptographic-Forum-Research-Group",
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
            Encoding.ASCII.GetBytes("Cryptographic Forum Research Group"),
            "a8061dc1305136c6c22b8baf0c0127a9"
        ),
        (
            "RFC8439-A.3-Zero-Key-Zero-Message",
            "0000000000000000000000000000000000000000000000000000000000000000",
            HexToBytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            "00000000000000000000000000000000"
        ),
        (
            "RFC8439-A.3-Polynomial-Wraparound-1",
            "0200000000000000000000000000000000000000000000000000000000000000",
            HexToBytes("ffffffffffffffffffffffffffffffff"),
            "03000000000000000000000000000000"
        ),
        (
            "RFC8439-A.3-Polynomial-Wraparound-2",
            "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
            HexToBytes("02000000000000000000000000000000"),
            "03000000000000000000000000000000"
        ),
        (
            "RFC8439-A.3-Multi-Block-Carry",
            "0100000000000000000000000000000000000000000000000000000000000000",
            HexToBytes("fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000"),
            "05000000000000000000000000000000"
        ),
        (
            "RFC8439-A.3-Twas-Brillig",
            "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
            HexToBytes("2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e"),
            "4541669a7eaaee61e708dc7cbcc5eb62"
        ),
        (
            "RFC8439-A.3-Accumulator-Final-Reduction",
            "0100000000000000040000000000000000000000000000000000000000000000",
            HexToBytes("e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000"),
            "14000000000000005500000000000000"
        )
    ];

    private static byte[] ComputeTag(byte[] key, byte[] message, int chunkSize)
    {
        using var keyPin = new PinnedMemory<byte>(key, false);
        using var mac = new global::Poly1305.NetCore.Poly1305(keyPin);

        for (var offset = 0; offset < message.Length; offset += chunkSize)
        {
            var length = Math.Min(chunkSize, message.Length - offset);
            mac.UpdateBlock(message, offset, length);
        }

        using var outputPin = new PinnedMemory<byte>(new byte[16], false);
        mac.DoFinal(outputPin, 0);

        var tag = outputPin.ToArray();
        return (byte[])tag.Clone();
    }

    private static byte[] HexToBytes(string hex) => Convert.FromHexString(hex);
}
