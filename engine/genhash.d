/+ dub.sdl:
name "genhash"
+/
import std.stdio;
import ircfiber.auth : hashPassword;
void main() {
    writeln(hashPassword("REDACTED"));
}
