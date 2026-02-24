# Poly1305.NetCore

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NuGet](https://img.shields.io/nuget/v/Poly1305.NetCore.svg)](https://www.nuget.org/packages/Poly1305.NetCore/)

`Poly1305.NetCore` is a .NET 8 implementation of the Poly1305 one-time message authentication code (MAC), originally designed by D. J. Bernstein and standardized in RFC 8439.

This package is built around the [`PinnedMemory`](https://github.com/TimothyMeadows/PinnedMemory) type to support memory pinning and explicit lifecycle control for sensitive material.

## Features

- Poly1305 MAC implementation with 16-byte authentication tag output.
- Uses a 32-byte key (`r || s`) with internal Poly1305 clamping.
- Supports incremental updates (`Update`, `UpdateBlock`) for streamed input.
- Clears internal state on `Dispose()`.
- Includes example app and RFC vector-based tests in this repository.

## Installation

### .NET CLI

```bash
dotnet add package Poly1305.NetCore
```

### Package Manager Console

```powershell
Install-Package Poly1305.NetCore
```

### NuGet

https://www.nuget.org/packages/Poly1305.NetCore/

## Requirements

- .NET 8.0+
- `PinnedMemory` dependency (pulled transitively from NuGet)

## Quick Start

```csharp
using Poly1305.NetCore;
using PinnedMemory;

var key = new byte[]
{
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xf1, 0xce,
    0xbf, 0xf9, 0x89, 0x7d, 0xe1, 0x45, 0x52, 0x4a
};

using var poly = new Poly1305(new PinnedMemory<byte>(key, false));
using var tag = new PinnedMemory<byte>(new byte[poly.GetLength()]);

poly.UpdateBlock(new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 }, 0, 11);
poly.DoFinal(tag, 0);

// tag now contains the 16-byte MAC
```

## API Overview

### Constructor

```csharp
Poly1305(PinnedMemory<byte> key)
```

- `key` must be exactly 32 bytes.

### Instance methods

```csharp
int GetLength()
```
Returns output tag length in bytes (always `16`).

```csharp
void Update(byte input)
```
Adds a single byte to the current MAC state.

```csharp
void UpdateBlock(byte[] input, int inOff, int len)
void UpdateBlock(PinnedMemory<byte> input, int inOff, int len)
```
Adds a range of bytes to the current MAC state.

```csharp
void DoFinal(PinnedMemory<byte> output, int outOff)
```
Writes the tag to `output` at `outOff` and resets message accumulator state.

```csharp
void Reset()
```
Resets message accumulator state while keeping the current key.

```csharp
void Dispose()
```
Clears internal state (including key material) and disposes internal pinned buffers.

## Usage Notes

- `DoFinal` finalizes the current message and then resets accumulator state, so the instance can process a new message with the same key.
- Use a new one-time key for each message (or each `(key, nonce)` derivation in protocols such as ChaCha20-Poly1305).
- Prefer `CryptographicOperations.FixedTimeEquals` when verifying tags.

## Security Notes

- Poly1305 is a **one-time authenticator**. Reusing the same Poly1305 one-time key for multiple different messages breaks security assumptions.
- This library zeroes internal buffers during `Dispose()`, but callers are still responsible for secure key generation, storage, and disposal of external buffers.
- Do not treat Poly1305 as encryption; it provides integrity/authentication only.

## Examples and Tests

- Runnable examples: `Poly1305.NetCore.Examples/`
- Test suite with RFC vectors: `Poly1305.NetCore.Tests/`

From repository root:

```bash
dotnet run --project Poly1305.NetCore.Examples
dotnet test
```

## Development

```bash
dotnet restore
dotnet build
dotnet test
```

## License

MIT. See [LICENSE](LICENSE).
