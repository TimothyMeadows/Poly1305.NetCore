# Poly1305.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet](https://img.shields.io/nuget/v/Poly1305.NetCore.svg)](https://www.nuget.org/packages/Poly1305.NetCore/)

`Poly1305.NetCore` is a .NET implementation of the [Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) one-time message authentication code (MAC).

The implementation uses [`PinnedMemory`](https://github.com/TimothyMeadows/PinnedMemory) for memory pinning and explicit lifecycle control of sensitive material.

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [API reference](#api-reference)
- [Behavior notes](#behavior-notes)
- [Best practices](#best-practices)
- [Validation and test vectors](#validation-and-test-vectors)
- [Development](#development)
- [Security notes](#security-notes)
- [License](#license)

---

## Requirements

- **.NET 8 SDK** for building and testing this repository.
- Target runtime/framework for this package: **.NET 8**.

---

## Installation

### NuGet Package Manager (CLI)

```bash
dotnet add package Poly1305.NetCore
```

### Package Manager Console

```powershell
Install-Package Poly1305.NetCore
```

### NuGet Gallery

- https://www.nuget.org/packages/Poly1305.NetCore/

---

## Quick start

```csharp
using System;
using Poly1305.NetCore;
using PinnedMemory;

var key = new byte[]
{
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xf1, 0xce,
    0xbf, 0xf9, 0x89, 0x7d, 0xe1, 0x45, 0x52, 0x4a
};

var message = new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 };

using var poly1305 = new Poly1305(new PinnedMemory<byte>(key, false));
using var tag = new PinnedMemory<byte>(new byte[poly1305.GetLength()]);

poly1305.UpdateBlock(message, 0, message.Length);
poly1305.DoFinal(tag, 0);

var tagHex = Convert.ToHexString(tag.ToArray()).ToLowerInvariant();
Console.WriteLine(tagHex);
```

---

## API reference

### Constructor

```csharp
Poly1305(PinnedMemory<byte> key)
```

- `key` must be exactly **32 bytes** (`r || s`).
- The lower half (`r`) is clamped internally per the Poly1305 specification.

### Core methods

```csharp
void Update(byte input)
void UpdateBlock(byte[] input, int inOff, int len)
void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)
void DoFinal(PinnedMemory<byte> output, int outOff)
void Reset()
int GetLength()
void Dispose()
```

### Output details

- `GetLength()` returns the tag size in **bytes**.
- The Poly1305 tag size is always **16 bytes**.

---

## Behavior notes

- `DoFinal(...)` finalizes the current message and then resets the accumulator state.
- `Reset()` clears message-specific state while preserving the current key.
- `Dispose()` zeroes and releases internal buffers, including key material.

---

## Best practices

### 1) Treat Poly1305 keys as one-time keys

- Poly1305 is a **one-time authenticator**.
- Reusing the same one-time key for different messages breaks security assumptions.

### 2) Use protocol-safe key derivation

- In modern protocols (for example ChaCha20-Poly1305), the Poly1305 one-time key is derived per message from a nonce and master key.
- Do not manually reuse a static 32-byte Poly1305 key across messages.

### 3) Verify tags in constant time

- Use `CryptographicOperations.FixedTimeEquals` when comparing tags.
- Avoid `SequenceEqual` or direct equality checks for secret-dependent comparisons.

### 4) Process large inputs incrementally

- Feed data via repeated `UpdateBlock(...)` calls for streaming scenarios.
- Avoid buffering full files/messages in memory when not necessary.

### 5) Dispose promptly

- Use `using` blocks for `Poly1305` and sensitive buffers.
- Dispose early when key material is no longer needed.

---

## Validation and test vectors

The test project validates behavior against RFC 8439 vectors and message processing semantics.

- RFC-based known answer vectors.
- Incremental update behavior (`Update` + `UpdateBlock`).
- Finalization and reset behavior.

Run from repository root:

```bash
dotnet test Poly1305.NetCore.sln
```

---

## Development

### Restore

```bash
dotnet restore Poly1305.NetCore.sln
```

### Build

```bash
dotnet build Poly1305.NetCore.sln
```

### Test

```bash
dotnet test Poly1305.NetCore.sln
```

---

## Security notes

- `Poly1305.NetCore` provides message authentication/integrity, not encryption.
- Ensure your full protocol defines nonce handling, key derivation, and replay protections.
- The library clears internal state on disposal, but callers remain responsible for secure key generation, storage, and external buffer handling.

---

## License

MIT. See [LICENSE](LICENSE).
