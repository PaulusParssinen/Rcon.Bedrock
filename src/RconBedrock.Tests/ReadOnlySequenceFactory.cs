// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Buffers;

namespace Rcon.Bedrock.Tests;

internal static class ReadOnlySequenceFactory
{
    sealed class BufferSegment : ReadOnlySequenceSegment<byte>
    {
        public BufferSegment(Memory<byte> memory) => Memory = memory;

        public BufferSegment Append(Memory<byte> memory)
        {
            Next = new BufferSegment(memory)
            {
                RunningIndex = RunningIndex + Memory.Length
            };
            return (BufferSegment)Next;
        }
    }

    public static ReadOnlySequence<byte> CreateSegments(params byte[][] inputs)
    {
        ArgumentNullException.ThrowIfNull(inputs);

        int i = 0;

        BufferSegment? last = null;
        BufferSegment? first = null;

        do
        {
            byte[] s = inputs[i];
            var chars = new byte[s.Length * 2];

            s.CopyTo(chars.AsSpan(s.Length));

            // Create a segment that has offset relative to the OwnedMemory and OwnedMemory itself has offset relative to array
            var memory = new Memory<byte>(chars).Slice(s.Length, s.Length);

            if (first is null)
            {
                first = new BufferSegment(memory);
                last = first;
            }
            else
            {
                last = last!.Append(memory);
            }
            i++;
        } while (i < inputs.Length);

        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }
}
