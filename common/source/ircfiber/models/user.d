module ircfiber.models.user;

import std.uuid;
import std.datetime : DateTime, SysTime, Clock, unixTimeToStdTime;
import vibe.data.json;
import vibe.data.bson;

/// User account
struct User {
    /// The user ID
    UUID id;
    /// The username
    string username;
    /// The email
    string email;
    /// The password hash
    string passwordHash;
    /// The roles
    string[] roles;
    /// The signup IP
    string signupIp;
    /// The IP used on last login
    string lastLoginIp;
    /// The time of last login
    SysTime lastLoginAt;
    /// The account creation time
    SysTime createdAt;
    /// IP history (de-duplicated list of login IPs)
    string[] loginIps;
    
    /// Serialize to JSON
    Json toJson() const {
        return Json([
            "id": Json(id.toString()),
            "username": Json(username),
            "email": Json(email),
            "passwordHash": Json(passwordHash),
            "roles": serializeToJson(roles),
            "signupIp": Json(signupIp),
            "lastLoginIp": Json(lastLoginIp),
            "lastLoginAt": Json(lastLoginAt.toUnixTime()),
            "createdAt": Json(createdAt.toUnixTime()),
            "loginIps": serializeToJson(loginIps)
        ]);
    }
    
    /// Deserialize from JSON
    static User fromJson(Json json) {
        User u;
        u.id = parseUUID(json["id"].get!string);
        u.username = json["username"].get!string;
        u.email = json["email"].get!string;
        u.passwordHash = json["passwordHash"].get!string;
        if (auto pr = "roles" in json)
            u.roles = deserializeJson!(string[])(*pr);
        if (auto pr = "signupIp" in json)
            u.signupIp = (*pr).get!string;
        if (auto pr = "lastLoginIp" in json)
            u.lastLoginIp = (*pr).get!string;
        if (auto pr = "lastLoginAt" in json) {
            auto ts = (*pr).get!long;
            if (ts > 0) u.lastLoginAt = SysTime(unixTimeToStdTime(ts));
        }
        if (auto pr = "createdAt" in json) {
            auto ts = (*pr).get!long;
            if (ts > 0) u.createdAt = SysTime(unixTimeToStdTime(ts));
        }
        if (auto pr = "loginIps" in json)
            u.loginIps = deserializeJson!(string[])(*pr);
        return u;
    }
}

@("User toJson serializes public fields")
unittest {
    User u;
    u.id = randomUUID();
    u.username = "alice";
    u.email = "alice@example.com";
    u.roles = ["user", "admin"];
    u.signupIp = "127.0.0.1";

    auto json = u.toJson();
    assert(json["id"].get!string == u.id.toString());
    assert(json["username"].get!string == "alice");
    assert(json["email"].get!string == "alice@example.com");
    assert(json["signupIp"].get!string == "127.0.0.1");
}

@("User fromJson deserializes all fields")
unittest {
    auto json = Json([
        "id": Json(randomUUID().toString()),
        "username": Json("alice"),
        "email": Json("alice@example.com"),
        "passwordHash": Json("hash123"),
        "roles": serializeToJson(["user", "admin"]),
        "signupIp": Json("192.168.1.1"),
        "lastLoginIp": Json("10.0.0.1"),
        "lastLoginAt": Json(1700000000),
        "createdAt": Json(1690000000),
        "loginIps": serializeToJson(["192.168.1.1", "10.0.0.1"])
    ]);

    const restored = User.fromJson(json);
    assert(restored.username == "alice");
    assert(restored.email == "alice@example.com");
    assert(restored.passwordHash == "hash123");
    assert(restored.roles == ["user", "admin"]);
    assert(restored.signupIp == "192.168.1.1");
    assert(restored.lastLoginIp == "10.0.0.1");
    assert(restored.loginIps == ["192.168.1.1", "10.0.0.1"]);
}
