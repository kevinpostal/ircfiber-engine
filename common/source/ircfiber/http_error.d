/**
 * User-facing REST error bodies: `{"error": <English text>, "code": <stable
 * snake_case id>, "params"?: {name: value}}`.
 *
 * `error` stays the English text older clients show verbatim; current
 * clients translate `code` (with `params` filling the `{name}` slots) and
 * fall back to `error` for codes they do not know.
 */
module ircfiber.http_error;

import vibe.data.json : Json;
import vibe.http.server : HTTPServerResponse;

/// `{"error": message, "code": code}` plus `"params"` only when non-empty.
Json apiErrorBody(string code, string message, string[string] params = null) @safe {
    auto j = Json.emptyObject;
    j["error"] = Json(message);
    j["code"] = Json(code);
    if (params.length > 0) {
        auto p = Json.emptyObject;
        foreach (k, v; params)
            p[k] = Json(v);
        j["params"] = p;
    }
    return j;
}

/// Sets `status` and writes `apiErrorBody(code, message, params)`.
void writeApiError(scope HTTPServerResponse res, int status, string code, string message,
        string[string] params = null) {
    res.statusCode = status;
    res.writeJsonBody(apiErrorBody(code, message, params));
}

unittest {
    auto a = apiErrorBody("network_not_found", "Network not found");
    assert(a["code"].get!string == "network_not_found" && a["error"].get!string == "Network not found");
    assert(a["params"].type == Json.Type.undefined);
    auto b = apiErrorBody("egress_exhausted", "all 3 slots are in use", ["count": "3"]);
    assert(b["params"]["count"].get!string == "3");
}
