using System.Text;
using System.Buffers;
using System.Diagnostics;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

using Bedrock.Framework.Protocols;

namespace Rcon.Bedrock;

public enum PacketType : int
{
    /// <summary>
    /// SERVERDATA_RESPONSE_VALUE
    /// </summary>
    ResponseValue = 0,
    /// <summary>
    /// SERVERDATA_AUTH_RESPONSE
    /// </summary>
    AuthResponse = 2,
    /// <summary>
    /// SERVERDATA_EXECCOMMAND
    /// </summary>
    ExecCommand = 2,
    /// <summary>
    /// SERVERDATA_AUTH
    /// </summary>
    Auth = 3
}

public readonly record struct RconMessage(int Id, PacketType Type, string Body);

public sealed class RconProtocol : IMessageReader<RconMessage>, IMessageWriter<RconMessage>
{
    private const int MinimumBodyLength = 10;

    public bool TryParseMessage(in ReadOnlySequence<byte> input, ref SequencePosition consumed, ref SequencePosition examined, out RconMessage message)
    {
        // TODO: If entire body is in FirstSpan, use fast-path.
        ReadOnlySpan<byte> inputSpan = input.FirstSpan;
        if (input.IsSingleSegment &&
            inputSpan.Length >= sizeof(int) + MinimumBodyLength)
        {
            int bodyLength = BinaryPrimitives.ReadInt32LittleEndian(inputSpan);
            if (bodyLength < MinimumBodyLength || inputSpan.Length - sizeof(int) < bodyLength)
            {
                message = default;
                return false;
            }

            int id = BinaryPrimitives.ReadInt32LittleEndian(inputSpan.Slice(sizeof(int)));
            var type = (PacketType)BinaryPrimitives.ReadInt32LittleEndian(inputSpan.Slice(2 * sizeof(int)));

            // Read null-terminated ASCII body.
            inputSpan = inputSpan.Slice(3 * sizeof(int));
            int terminatorIndex = inputSpan.IndexOf((byte)0);
            string body = Encoding.ASCII.GetString(inputSpan.Slice(0, terminatorIndex));

            message = new RconMessage(id, type, body);
            
            consumed = input.GetPosition(3 * sizeof(int) + terminatorIndex + 2, input.Start);
            examined = consumed;
            return true;
        }
        else return TryParseMultiSegment(in input, ref consumed, ref examined, out message);

        static bool TryParseMultiSegment(in ReadOnlySequence<byte> input, ref SequencePosition consumed, ref SequencePosition examined, out RconMessage message)
        {
            var reader = new SequenceReader<byte>(input);

            if (reader.TryReadLittleEndian(out int length) && 
                length < MinimumBodyLength || reader.Remaining < length ||
                !reader.TryReadLittleEndian(out int id) ||
                !reader.TryReadLittleEndian(out int type))
            {
                message = default;
                examined = reader.Position;
                return false;
            }

            reader.TryReadTo(out ReadOnlySpan<byte> bodySlice, 0, advancePastDelimiter: true);
            string body = Encoding.ASCII.GetString(bodySlice);
            
            message = new RconMessage(id, (PacketType)type, body);

            // Skip last null-terminator.
            Debug.Assert(reader.TryPeek(out byte terminator) && terminator == 0);
            reader.Advance(1);

            consumed = reader.Position;
            examined = consumed;
            return true;
        }
    }

    public void WriteMessage(RconMessage message, IBufferWriter<byte> output)
    {
        int bodyLength = MinimumBodyLength + Encoding.ASCII.GetByteCount(message.Body);
        int bufferLength = sizeof(int) + bodyLength;

        Span<byte> buffer = output.GetSpan(bufferLength).Slice(0, bufferLength);

        // Write two null-terminator bytes to the end of the message.
        MemoryMarshal.Write<ushort>(buffer.Slice(buffer.Length - sizeof(ushort)), 0);

        BinaryPrimitives.WriteInt32LittleEndian(buffer, bodyLength);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(4), message.Id);
        BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(8), (int)message.Type);
        Encoding.ASCII.GetBytes(message.Body, buffer.Slice(12));

        output.Advance(bufferLength);
    }
}