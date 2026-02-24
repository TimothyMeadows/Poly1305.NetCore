# Poly1305.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/Poly1305.NetCore.svg)](https://www.nuget.org/packages/Poly1305.NetCore/)

Implementation of the Poly1305 one-time message authentication code, designed by D. J. Bernstein and standardized in RFC 8439. Optimized for [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory).

# Install

From a command prompt
```bash
dotnet add package Poly1305.NetCore
```

```bash
Install-Package Poly1305.NetCore
```

You can also search for package via your nuget ui / website:

https://www.nuget.org/packages/Poly1305.NetCore/

# Examples

You can find more examples in the github examples project.

```csharp
var key = new byte[] {
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xf1, 0xce,
    0xbf, 0xf9, 0x89, 0x7d, 0xe1, 0x45, 0x52, 0x4a
};

using var poly = new Poly1305(new PinnedMemory<byte>(key, false));
using var hash = new PinnedMemory<byte>(new byte[poly.GetLength()]);
poly.UpdateBlock(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, 0, 11);
poly.DoFinal(hash, 0);
```

# Constructor

```csharp
Poly1305(PinnedMemory<byte> key)
```

# Methods

Set key for digest, this is typically only used if the key changes after construction.
```csharp
void SetKey(PinnedMemory<byte> key)
```

Get the message digest output length.
```csharp
int GetLength()
```

Update the message digest with a single byte.
```csharp
void Update(byte input)
```

Update the message digest with a pinned memory byte array.
```csharp
void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)
```

Update the message digest with a byte array.
```csharp
void UpdateBlock(byte[] input, int inOff, int len)
```

Produce the final digest value outputting to pinned memory. Key & salt remain until dispose is called.
```csharp
void DoFinal(PinnedMemory<byte> output, int outOff)
```

Reset the digest back to it's initial state for further processing. Key & salt remain until dispose is called.
```csharp
void Reset()
```

Clear key & salt, reset digest back to it's initial state.
```csharp
void Dispose()
```


## Security Notes

- Poly1305 is a **one-time authenticator**: never reuse the same (r, s) key pair for different messages (RFC 8439).
- This library clears internal state in `Dispose()`; callers are still responsible for lifecycle and secure generation/storage of keys.
- Compare authentication tags using constant-time methods such as `CryptographicOperations.FixedTimeEquals`.
