module ircfiber.engine.event_channel;

import core.time : Duration;
import std.exception : enforce;
import std.algorithm.mutation : move;
import vibe.core.channel : Channel, createChannel;
import ircfiber.models.irc_event : IRCRawEvent;

/// Event-loop-owned admission gate shared by every engine event producer.
/// Channel.close alone is insufficient: vibe's full-ring put checks closure
/// before waiting, not after it wakes. Count those puts until they actually
/// finish before admitting the private FIFO shutdown marker.
struct EngineEventChannel {
    enum bufferSize = Channel!IRCRawEvent.bufferSize;
    private static final class State {
        Channel!IRCRawEvent channel;
        size_t puts;
        bool fenced;
        this() { channel = createChannel!IRCRawEvent(); }
    }
    private State state;

    static EngineEventChannel create() {
        EngineEventChannel result;
        result.state = new State;
        return result;
    }

    void put(IRCRawEvent event) {
        enforce(state !is null && !state.fenced, "Engine event ingress is closed.");
        ++state.puts;
        scope(exit) --state.puts;
        state.channel.put(event.move);
    }

    /// Synchronous, no yield: later producers cannot enter a channel put.
    void fence() nothrow @safe { if (state !is null) state.fenced = true; }
    bool producersDrained() const nothrow @safe {
        return state !is null && state.fenced && state.puts == 0;
    }

    /// Only engine internals may bypass the public producer fence. The
    /// controller authenticates the marker separately with a private nonce.
    package(ircfiber.engine) void putShutdownMarker(IRCRawEvent event) {
        enforce(producersDrained(), "Engine event producers are not drained.");
        state.channel.put(event.move);
    }

    void close() {
        fence();
        enforce(producersDrained(), "Closing engine event ingress with pending puts.");
        state.channel.close();
    }

    bool tryConsumeOne(ref IRCRawEvent event, Duration timeout = Duration.max) {
        return state.channel.tryConsumeOne(event, timeout);
    }
    size_t bufferFill() nothrow @safe { return state.channel.bufferFill; }
}
