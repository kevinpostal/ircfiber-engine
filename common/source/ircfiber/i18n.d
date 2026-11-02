/**
 * UI languages, sign-up language negotiation and the few server-side
 * strings that reach users (emails, push bodies).
 *
 * `en` is the source and fallback. The web SPA and the iOS app keep their
 * own catalogs; this module only holds what the gateway itself sends.
 */
module ircfiber.i18n;

import std.algorithm.iteration : map, splitter;
import std.algorithm.searching : canFind;
import std.array : array, replace;
import std.string : indexOf, strip, toLower, toUpper;

/// Account `language` values besides `""` (automatic).
immutable string[] SUPPORTED_LANGUAGES = ["en", "es", "pt-BR", "fr", "de", "it", "ru", "tr"];

/// Exact, case-sensitive membership in `SUPPORTED_LANGUAGES`.
bool isSupportedLanguage(string code) @safe pure nothrow {
    foreach (s; SUPPORTED_LANGUAGES)
        if (s == code) return true;
    return false;
}

/// Maps a BCP 47-ish tag (`pt_PT`, `en-GB`, `de`) to a supported code, or `""`.
string matchLanguageTag(string tag) @safe pure {
    const t = tag.strip.toLower.replace("_", "-");
    if (t.length == 0) return "";
    foreach (s; SUPPORTED_LANGUAGES)
        if (s.toLower == t) return s;
    const dash = t.indexOf('-');
    const primary = dash < 0 ? t : t[0 .. dash];
    if (primary == "pt") return "pt-BR";
    foreach (s; SUPPORTED_LANGUAGES)
        if (s == primary) return s;
    return "";
}

/// Tags of an `Accept-Language` header, highest q first (stable). `*` and
/// q ≤ 0 are dropped; a missing q is 1.0, an unparsable one 0.
string[] parseAcceptLanguage(string header) @safe {
    import std.algorithm.sorting : sort;
    import std.algorithm.mutation : SwapStrategy;
    import std.conv : to;

    static struct Item { string tag; double q; }
    Item[] items;
    foreach (raw; header.splitter(',')) {
        auto parts = raw.splitter(';');
        if (parts.empty) continue;
        const tag = parts.front.strip;
        parts.popFront();
        double q = 1.0;
        foreach (p; parts) {
            const kv = p.strip;
            if (kv.length >= 2 && (kv[0] == 'q' || kv[0] == 'Q') && kv[1] == '=') {
                try q = kv[2 .. $].strip.to!double;
                catch (Exception) q = 0;
            }
        }
        if (tag.length == 0 || tag == "*" || !(q > 0)) continue;
        items ~= Item(tag, q);
    }
    items.sort!((a, b) => a.q > b.q, SwapStrategy.stable);
    return items.map!(i => i.tag).array;
}

/// Language most users in a country read, for `CF-IPCountry`; `""` when unmapped.
string languageForCountry(string iso2) @safe pure {
    switch (iso2.strip.toUpper) {
    case "ES": case "MX": case "AR": case "CO": case "CL": case "PE": case "VE":
    case "EC": case "GT": case "CU": case "BO": case "DO": case "HN": case "PY":
    case "SV": case "NI": case "CR": case "PA": case "UY": case "PR": case "GQ":
        return "es";
    case "BR": case "PT": case "AO": case "MZ": case "CV": case "GW": case "ST": case "TL":
        return "pt-BR";
    case "FR": case "MC": case "SN": case "CI": case "ML": case "BF": case "NE": case "TG":
    case "BJ": case "GN": case "CD": case "CG": case "GA": case "CM": case "MG": case "HT":
        return "fr";
    case "DE": case "AT": case "CH": case "LI":
        return "de";
    case "IT": case "SM": case "VA":
        return "it";
    case "RU": case "BY": case "KZ": case "KG":
        return "ru";
    case "TR":
        return "tr";
    default:
        return "";
    }
}

/// Sign-up language: the browser's list (comma-separated, in order), then
/// `Accept-Language`, then the country, then `en`. Never `""`.
string negotiateSignupLanguage(string browserLangs, string acceptLanguage, string country) @safe {
    foreach (tag; browserLangs.splitter(',')) {
        const m = matchLanguageTag(tag);
        if (m.length) return m;
    }
    foreach (tag; parseAcceptLanguage(acceptLanguage)) {
        const m = matchLanguageTag(tag);
        if (m.length) return m;
    }
    const c = languageForCountry(country);
    if (c.length) return c;
    return "en";
}

/// Server text `key` in `lang` (falling back to `en`), with each `{name}`
/// replaced by `params[name]`. Keys are compile-time literals: an unknown
/// key is a programming error.
string serverText(string lang, string key, string[string] params = null) @safe {
    string s;
    if (auto table = lang in TEXT)
        if (auto p = key in *table) s = *p;
    if (s is null) {
        auto p = key in TEXT["en"];
        if (p is null) assert(0, "unknown server text key: " ~ key);
        s = *p;
    }
    foreach (name, value; params)
        s = s.replace("{" ~ name ~ "}", value);
    return s;
}

immutable string[string][string] TEXT;

shared static this() {
    string[string][string] t;
    t["en"] = [
        "email.greeting": "Hi {username},",
        "email.verify.subject": "Confirm your IRC Fiber account",
        "email.verify.intro": "Confirm your email address to finish creating your IRC Fiber account:",
        "email.verify.expiry": "This link expires in 24 hours. If you did not sign up, ignore this email: no account is created until the link is used.",
        "email.reset.subject": "Reset your IRC Fiber password",
        "email.reset.intro": "Follow the link below to set a new IRC Fiber password:",
        "email.reset.expiry": "This link expires in 1 hour. If you did not ask for a reset, ignore this email: your password is unchanged.",
        "push.invite.body": "{nick} invited you to {channel}",
    ];
    t["es"] = [
        "email.greeting": "Hola, {username}:",
        "email.verify.subject": "Confirma tu cuenta de IRC Fiber",
        "email.verify.intro": "Confirma tu dirección de correo electrónico para terminar de crear tu cuenta de IRC Fiber:",
        "email.verify.expiry": "Este enlace caduca en 24 horas. Si no te registraste, ignora este correo: no se crea ninguna cuenta hasta que se use el enlace.",
        "email.reset.subject": "Restablece tu contraseña de IRC Fiber",
        "email.reset.intro": "Sigue el enlace de abajo para establecer una nueva contraseña de IRC Fiber:",
        "email.reset.expiry": "Este enlace caduca en 1 hora. Si no solicitaste restablecerla, ignora este correo: tu contraseña no ha cambiado.",
        "push.invite.body": "{nick} te invitó a {channel}",
    ];
    t["pt-BR"] = [
        "email.greeting": "Olá, {username},",
        "email.verify.subject": "Confirme sua conta do IRC Fiber",
        "email.verify.intro": "Confirme seu endereço de e-mail para concluir a criação da sua conta do IRC Fiber:",
        "email.verify.expiry": "Este link expira em 24 horas. Se você não se cadastrou, ignore este e-mail: nenhuma conta é criada até que o link seja usado.",
        "email.reset.subject": "Redefina sua senha do IRC Fiber",
        "email.reset.intro": "Siga o link abaixo para definir uma nova senha do IRC Fiber:",
        "email.reset.expiry": "Este link expira em 1 hora. Se você não pediu uma redefinição, ignore este e-mail: sua senha não foi alterada.",
        "push.invite.body": "{nick} convidou você para {channel}",
    ];
    t["fr"] = [
        "email.greeting": "Bonjour {username},",
        "email.verify.subject": "Confirmez votre compte IRC Fiber",
        "email.verify.intro": "Confirmez votre adresse e-mail pour terminer la création de votre compte IRC Fiber :",
        "email.verify.expiry": "Ce lien expire dans 24 heures. Si vous ne vous êtes pas inscrit, ignorez cet e-mail : aucun compte n’est créé tant que le lien n’est pas utilisé.",
        "email.reset.subject": "Réinitialisez votre mot de passe IRC Fiber",
        "email.reset.intro": "Suivez le lien ci-dessous pour définir un nouveau mot de passe IRC Fiber :",
        "email.reset.expiry": "Ce lien expire dans 1 heure. Si vous n’avez pas demandé de réinitialisation, ignorez cet e-mail : votre mot de passe reste inchangé.",
        "push.invite.body": "{nick} vous a invité sur {channel}",
    ];
    t["de"] = [
        "email.greeting": "Hallo {username},",
        "email.verify.subject": "Bestätige dein IRC Fiber-Konto",
        "email.verify.intro": "Bestätige deine E-Mail-Adresse, um die Erstellung deines IRC Fiber-Kontos abzuschließen:",
        "email.verify.expiry": "Dieser Link läuft in 24 Stunden ab. Wenn du dich nicht registriert hast, ignoriere diese E-Mail: Ein Konto wird erst erstellt, wenn der Link verwendet wird.",
        "email.reset.subject": "Setze dein IRC Fiber-Passwort zurück",
        "email.reset.intro": "Folge dem Link unten, um ein neues IRC Fiber-Passwort festzulegen:",
        "email.reset.expiry": "Dieser Link läuft in 1 Stunde ab. Wenn du keine Zurücksetzung angefordert hast, ignoriere diese E-Mail: Dein Passwort bleibt unverändert.",
        "push.invite.body": "{nick} hat dich in {channel} eingeladen",
    ];
    t["it"] = [
        "email.greeting": "Ciao {username},",
        "email.verify.subject": "Conferma il tuo account IRC Fiber",
        "email.verify.intro": "Conferma il tuo indirizzo email per completare la creazione del tuo account IRC Fiber:",
        "email.verify.expiry": "Questo link scade tra 24 ore. Se non ti sei registrato, ignora questa email: nessun account viene creato finché il link non viene usato.",
        "email.reset.subject": "Reimposta la tua password di IRC Fiber",
        "email.reset.intro": "Segui il link qui sotto per impostare una nuova password di IRC Fiber:",
        "email.reset.expiry": "Questo link scade tra 1 ora. Se non hai richiesto una reimpostazione, ignora questa email: la tua password non è cambiata.",
        "push.invite.body": "{nick} ti ha invitato in {channel}",
    ];
    t["ru"] = [
        "email.greeting": "Здравствуйте, {username}!",
        "email.verify.subject": "Подтвердите учётную запись IRC Fiber",
        "email.verify.intro": "Подтвердите адрес электронной почты, чтобы завершить создание учётной записи IRC Fiber:",
        "email.verify.expiry": "Ссылка действительна 24 часа. Если вы не регистрировались, проигнорируйте это письмо: учётная запись не будет создана, пока ссылка не использована.",
        "email.reset.subject": "Сброс пароля IRC Fiber",
        "email.reset.intro": "Перейдите по ссылке ниже, чтобы задать новый пароль IRC Fiber:",
        "email.reset.expiry": "Ссылка действительна 1 час. Если вы не запрашивали сброс, проигнорируйте это письмо: ваш пароль не изменился.",
        "push.invite.body": "{nick} приглашает вас в {channel}",
    ];
    t["tr"] = [
        "email.greeting": "Merhaba {username},",
        "email.verify.subject": "IRC Fiber hesabınızı onaylayın",
        "email.verify.intro": "IRC Fiber hesabınızı oluşturmayı tamamlamak için e-posta adresinizi onaylayın:",
        "email.verify.expiry": "Bu bağlantının süresi 24 saat içinde dolar. Kaydolmadıysanız bu e-postayı yok sayın: bağlantı kullanılana kadar hesap oluşturulmaz.",
        "email.reset.subject": "IRC Fiber parolanızı sıfırlayın",
        "email.reset.intro": "Yeni bir IRC Fiber parolası belirlemek için aşağıdaki bağlantıyı izleyin:",
        "email.reset.expiry": "Bu bağlantının süresi 1 saat içinde dolar. Sıfırlama isteğinde bulunmadıysanız bu e-postayı yok sayın: parolanız değişmedi.",
        "push.invite.body": "{nick} sizi {channel} kanalına davet etti",
    ];
    TEXT = cast(immutable) t;
}

unittest {
    assert(parseAcceptLanguage("ja, de;q=0.8, fr;q=0, *;q=0.1") == ["ja", "de"]);
    assert(parseAcceptLanguage("de;q=0.5, en;q=0.9, fr") == ["fr", "en", "de"]);
    assert(parseAcceptLanguage("de;q=abc, en") == ["en"]);

    assert(matchLanguageTag("pt-br") == "pt-BR");
    assert(matchLanguageTag("en_GB") == "en");
    assert(matchLanguageTag("de-AT") == "de");
    assert(matchLanguageTag("ja") == "");
    assert(languageForCountry("br") == "pt-BR");

    assert(negotiateSignupLanguage("fr-CA,en", "de", "BR") == "fr");
    assert(negotiateSignupLanguage("ja", "ja, de;q=0.8", "BR") == "de");
    assert(negotiateSignupLanguage("", "ja", "BR") == "pt-BR");
    assert(negotiateSignupLanguage("", "", "JP") == "en");
    assert(negotiateSignupLanguage("pt-PT", "", "") == "pt-BR");

    assert(isSupportedLanguage("pt-BR") && !isSupportedLanguage("pt-br") && !isSupportedLanguage(""));
}

unittest {
    assert(serverText("de", "push.invite.body", ["nick": "al", "channel": "#x"]) == "al hat dich in #x eingeladen");
    assert(serverText("", "push.invite.body", ["nick": "al", "channel": "#x"]) == "al invited you to #x");
    assert(serverText("xx", "email.verify.subject") == "Confirm your IRC Fiber account");
}

unittest {
    // Every language carries every English key with the same placeholders.
    import std.algorithm.sorting : sort;
    import std.regex : ctRegex, matchAll;

    static string[] placeholders(string s) {
        string[] names;
        foreach (m; s.matchAll(ctRegex!`\{([A-Za-z]+)\}`))
            names ~= m[1];
        names.sort();
        return names;
    }

    foreach (lang; SUPPORTED_LANGUAGES) {
        assert(lang in TEXT, "missing server text language " ~ lang);
        foreach (key, en; TEXT["en"]) {
            auto p = key in TEXT[lang];
            assert(p !is null, lang ~ " lacks " ~ key);
            assert((*p).length > 0, lang ~ " empty " ~ key);
            assert(placeholders(*p) == placeholders(en), lang ~ " placeholder mismatch in " ~ key);
        }
        assert(TEXT[lang].length == TEXT["en"].length, lang ~ " has extra keys");
    }
}
