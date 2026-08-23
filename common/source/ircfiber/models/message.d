module ircfiber.models.message;

import std.datetime;
import std.uuid;
import vibe.data.json;
import std.conv;

/// Message type
enum MessageType {
    /// Regular message
    message,
    /// Action (/me)
    action,
    /// Notice
    notice,
    /// Join event
    join,
    /// Part event
    part,
    /// Quit event
    quit,
    /// Topic change
    topic,
    /// Mode change
    mode,
    /// Nick change
    nick
}

/// IRC message
struct Message {
    /// The message ID
    UUID id;
    /// The network name
    string network;
    /// The channel name
    string channel;
    /// The sender nick
    string nick;
    /// The display nick
    string displayNick;
    /// The message text
    string text;
    /// The timestamp
    SysTime timestamp;
    /// The message type
    MessageType type;
    /// The tags
    Json tags;
    /// Whether this is a highlight
    bool isHighlight;
    /// The rendered text
    string renderedText;
    /// The nick CSS class
    string nickClass;
    /// The message ID (IRCv3 msgid)
    string msgid;
    /// The label (IRCv3 labeled-response)
    string label;
    
    /// Serialize to JSON
    Json toJson() const {
        return Json([
            "id": Json(id.toString()),
            "network": Json(network),
            "channel": Json(channel),
            "nick": Json(nick),
            "text": Json(text),
            "timestamp": Json(timestamp.toISOExtString()),
            "type": Json(type.to!string),
            "isHighlight": Json(isHighlight),
            "msgid": Json(msgid),
            "label": Json(label)
        ]);
    }
    
    /// Serialize to abbreviated JSON
    Json toAbbreviatedJson() const {
        return Json([
            "i": Json(id.toString()),
            "t": Json(timestamp.toISOExtString()),
            "n": Json(nick),
            "x": Json(text),
            "y": Json(abbreviatedType()),
            "m": Json(msgid),
            "l": Json(label)
        ]);
    }
    
    private string abbreviatedType() const {
        switch (type) {
            case MessageType.message: return "m";
            case MessageType.action: return "a";
            case MessageType.notice: return "n";
            case MessageType.join: return "j";
            case MessageType.part: return "p";
            case MessageType.quit: return "q";
            case MessageType.topic: return "t";
            case MessageType.mode: return "o";
            case MessageType.nick: return "c";
            default: return "m";
        }
    }
}

@("Message abbreviated type mapping")
unittest {
    Message m;
    m.type = MessageType.action;
    assert(m.toAbbreviatedJson()["y"].get!string == "a");

    m.type = MessageType.join;
    assert(m.toAbbreviatedJson()["y"].get!string == "j");

    m.type = MessageType.nick;
    assert(m.toAbbreviatedJson()["y"].get!string == "c");
}

@("Message toJson includes core fields")
unittest {
    Message m;
    m.id = randomUUID();
    m.network = "libera";
    m.channel = "#d";
    m.nick = "alice";
    m.text = "hello";
    m.type = MessageType.message;
    m.isHighlight = true;

    auto json = m.toJson();
    assert(json["network"].get!string == "libera");
    assert(json["channel"].get!string == "#d");
    assert(json["nick"].get!string == "alice");
    assert(json["text"].get!string == "hello");
    assert(json["type"].get!string == "message");
    assert(json["isHighlight"].get!bool == true);
}
