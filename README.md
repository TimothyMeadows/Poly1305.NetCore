# Poly1305.NetCore
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![nuget](https://img.shields.io/nuget/v/Poly1305.NetCore.svg)](https://www.nuget.org/packages/Poly1305.NetCore/)

Implementation of poly1305-dona message authentication code, designed by D. J. Bernstein. Optimized for [PinnedMemory](https://github.com/TimothyMeadows/PinnedMemory).

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
using var poly = new Poly1305(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77}, false));
using var hash = new PinnedMemory<byte>(new byte[digest.GetLength()]);
digest.UpdateBlock(new PinnedMemory<byte>(new byte[] {63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77}, false), 0, 11);
digest.DoFinal(hash, 0);
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
