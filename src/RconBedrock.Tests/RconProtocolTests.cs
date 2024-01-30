using System.Buffers;

namespace Rcon.Bedrock.Tests;

public sealed class RconProtocolTests
{
    [Fact]
    public void WriteMessage_AuthenticationWithPassword()
    {
        ArrayBufferWriter<byte> output = new ArrayBufferWriter<byte>(21);

        var protocol = new RconProtocol();
        protocol.WriteMessage(new RconMessage
        {
            Id = 0,
            Type = PacketType.Auth,
            Body = "passwrd"
        }, output);

        Assert.Equal(output.WrittenSpan.ToArray(), 
            [0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, .. "passwrd"u8, 0x00, 0x00]);
    }

    [Fact]
    public void WriteMessage_AuthenticationWithoutPassword()
    {
        ArrayBufferWriter<byte> output = new ArrayBufferWriter<byte>(21);

        var protocol = new RconProtocol();
        protocol.WriteMessage(new RconMessage
        {
            Id = 0,
            Type = PacketType.Auth,
            Body = string.Empty
        }, output);

        Assert.Equal(output.WrittenSpan.ToArray(),
            [0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    [Fact]
    public void TryParseMessage_SingleSegment_EmptyBody()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = new ReadOnlySequence<byte>(
            [0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]);

        bool success = new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.True(success);
        Assert.Equal(0, message.Id);
        Assert.Equal(PacketType.AuthResponse, message.Type);
        Assert.Equal(string.Empty, message.Body);

        Assert.Equal(inputSequence.End, consumed);
        Assert.Equal(inputSequence.End, examined);
    }

    [Fact]
    public void TryParseMessage_MultiSegment_ThreeSegments_EmptyBody()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = ReadOnlySequenceFactory.CreateSegments(
            [0x0A, 0x00, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00], [0x00, 0x00, 0x00]);

        bool success = new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.True(success);
        Assert.Equal(0, message.Id);
        Assert.Equal(PacketType.AuthResponse, message.Type);
        Assert.Equal(string.Empty, message.Body);

        Assert.Equal(inputSequence.End, consumed);
        Assert.Equal(inputSequence.End, examined);
    }

    [Fact]
    public void TryParseMessage_SingleSegment()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = new ReadOnlySequence<byte>(
            [0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, .. "HLSW : Test"u8, 0x00, 0x00]);
        
        bool success =  new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.True(success);
        Assert.Equal(0, message.Id);
        Assert.Equal(PacketType.ResponseValue, message.Type);
        Assert.Equal("HLSW : Test", message.Body);

        Assert.Equal(inputSequence.End, consumed);
        Assert.Equal(inputSequence.End, examined);
    }

    [Fact]
    public void TryParseMessage_MultiSegment_BodySplit()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = ReadOnlySequenceFactory.CreateSegments(
            [0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, .. "HLSW"u8], [.." : Test"u8, 0x00, 0x00]);

        bool success = new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.True(success); 
        Assert.Equal(0, message.Id);
        Assert.Equal(PacketType.ResponseValue, message.Type);
        Assert.Equal("HLSW : Test", message.Body);

        Assert.Equal(inputSequence.End, consumed);
        Assert.Equal(inputSequence.End, examined);
    }

    [Fact]
    public void TryParseMessage_MultiSegment_ThreeSegments()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = ReadOnlySequenceFactory.CreateSegments(
            [0x15, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, .. "HLSW"u8], [.. " : Test"u8, 0x00, 0x00]);

        bool success = new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.True(success);
        Assert.Equal(0, message.Id);
        Assert.Equal(PacketType.ResponseValue, message.Type);
        Assert.Equal("HLSW : Test", message.Body);

        Assert.Equal(inputSequence.End, consumed);
        Assert.Equal(inputSequence.End, examined);
    }

    [Fact]
    public void TryParseMessage_MultiSegment_AfterLengthSplit()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = ReadOnlySequenceFactory.CreateSegments(
            [0x15, 0x00, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, .. "HLSW : Test"u8, 0x00, 0x00]);

        bool success = new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.True(success);
        Assert.Equal(0, message.Id);
        Assert.Equal(PacketType.ResponseValue, message.Type);
        Assert.Equal("HLSW : Test", message.Body);

        Assert.Equal(inputSequence.End, consumed);
        Assert.Equal(inputSequence.End, examined);
    }

    [Fact]
    public void TryParseMessage_EmptyInput_ShouldFail()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = new ReadOnlySequence<byte>();

        bool success = new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.False(success);
        Assert.Equal(default, message);

        Assert.Equal(0, inputSequence.GetOffset(consumed));
        Assert.Equal(0, inputSequence.GetOffset(examined));
    }

    [Fact]
    public void TryParseMessage_SingleSegment_TooShortInput_ShouldFail()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = new ReadOnlySequence<byte>(
            [0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        bool success = new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.False(success);
        Assert.Equal(default, message);

        Assert.Equal(0, inputSequence.GetOffset(consumed));
        Assert.Equal(4, inputSequence.GetOffset(examined));
    }

    [Fact]
    public void TryParseMessage_MultiSegment_TooShortInput_ShouldFail()
    {
        SequencePosition consumed = default, examined = default;
        var inputSequence = ReadOnlySequenceFactory.CreateSegments(
            [0x15, 0x00, 0x00], [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        bool success = new RconProtocol().TryParseMessage(inputSequence, ref consumed, ref examined, out var message);

        Assert.False(success);
        Assert.Equal(default, message);

        Assert.Equal(0, inputSequence.GetOffset(consumed));
        Assert.Equal(4, inputSequence.GetOffset(examined));
    }
}