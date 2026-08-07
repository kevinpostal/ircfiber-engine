module ircfiber.models.ircchannel;

import std.datetime;
import vibe.data.json;

/// IRC channel
struct IRCChannel {
    /// The channel name
    string name;
    /// The channel topic
    string topic;
    /// Who set the topic
    string topicSetBy;
    /// When the topic was set
    SysTime topicSetAt;
    /// Channel users (nick -> prefix)
    string[string] users;
    /// Channel modes
    string[] modes;
    /// Unread message count
    long unreadCount;
    /// Whether joined
    bool isJoined;
    
    /// Serialize to JSON
    Json toJson() const {
        auto userArr = Json.emptyArray;
        foreach (nick, prefix; users) {
            userArr ~= Json([
                "nick": Json(nick),
                "prefix": Json(prefix)
            ]);
        }
        
        return Json([
            "name": Json(name),
            "topic": Json(topic),
            "topicSetBy": Json(topicSetBy),
            "topicSetAt": Json(topicSetAt.toISOExtString()),
            "users": userArr,
            "modes": serializeToJson(modes),
            "unreadCount": Json(unreadCount),
            "isJoined": Json(isJoined)
        ]);
    }
}

@("IRCChannel toJson serializes users correctly")
unittest {
    IRCChannel ch;
    ch.name = "#d";
    ch.topic = "D language";
    ch.users = ["alice": "@", "bob": "+"];
    ch.unreadCount = 5;
    ch.isJoined = true;

    auto json = ch.toJson();
    assert(json["name"].get!string == "#d");
    assert(json["topic"].get!string == "D language");
    assert(json["unreadCount"].get!long == 5);
    assert(json["isJoined"].get!bool == true);
}
