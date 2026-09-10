module ircfiber.models.user;

import std.uuid;
import std.datetime : DateTime, SysTime, Clock, unixTimeToStdTime;
import vibe.data.json;
import vibe.data.bson;

/// One linked social-login identity: provider name ("github") plus the
/// provider-side user id as a string.
struct OAuthIdentity {
    string provider;
    string subject;
}
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
    /// How this account was provisioned: "" = normal signup,
    /// "nickserv:<account>" = created by !adduser from a NickServ account.
    string provisionedFrom;
    /// The IP used on last login
    string lastLoginIp;
    /// The time of last login
    SysTime lastLoginAt;
    /// Bulk-campaign opt-out. Default false keeps every existing row
    /// subscribed; set via the List-Unsubscribe flow (no migration needed —
    /// missing key reads as false).
    bool emailUnsubscribed = false;
    /// Linked social-login identities. Default [] keeps every existing row
    /// unlinked with no migration; missing key reads as [].
    OAuthIdentity[] oauthIdentities;
    /// The account creation time
    SysTime createdAt;
    /// IP history (de-duplicated list of login IPs)
    string[] loginIps;
    /// Serialize to JSON
    Json toJson() const {
        Json[] ids;
        foreach (o; oauthIdentities)
            ids ~= Json(["provider": Json(o.provider), "subject": Json(o.subject)]);
        return Json([
            "id": Json(id.toString()),
            "username": Json(username),
            "email": Json(email),
            "passwordHash": Json(passwordHash),
            "roles": serializeToJson(roles),
            "signupIp": Json(signupIp),
            "provisionedFrom": Json(provisionedFrom),
            "lastLoginIp": Json(lastLoginIp),
            "lastLoginAt": Json(lastLoginAt.toUnixTime()),
            "createdAt": Json(createdAt.toUnixTime()),
            "loginIps": serializeToJson(loginIps),
            "emailUnsubscribed": Json(emailUnsubscribed),
            "oauthIdentities": Json(ids)
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
        if (auto pr = "provisionedFrom" in json)
            u.provisionedFrom = (*pr).get!string;
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
        // Missing key (pre-campaign rows) reads as false: still subscribed.
        if (auto pr = "emailUnsubscribed" in json)
            u.emailUnsubscribed = (*pr).get!bool;
        // Missing key (pre-OAuth rows) reads as []: unlinked.
        if (auto pr = "oauthIdentities" in json) {
            try {
                foreach (e; (*pr).get!(Json[]))
                    u.oauthIdentities ~= OAuthIdentity(e["provider"].get!string, e["subject"].get!string);
            } catch (Exception) { u.oauthIdentities = []; }
        }
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
        "lastLoginAt": Json(1_700_000_000),
        "createdAt": Json(1_690_000_000),
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
