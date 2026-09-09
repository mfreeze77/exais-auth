#!/bin/sh
# ExpertAuth contributors, 2026. Apache-2.0. Explicit source-native runtime profile.
set -eu
fail() { printf '%s\n' "$1" >&2; exit 78; }
native=/opt/expertauth/native
expected=@ARGON2_SHA256@
case "${JAVA_TOOL_OPTIONS-} ${JDK_JAVA_OPTIONS-} ${_JAVA_OPTIONS-}" in
    *jna.*) fail NATIVE_ARGON2_RUNTIME_OPTIONS_REJECTED ;;
esac
[ -f "$native/libargon2.so" ] && [ ! -L "$native/libargon2.so" ] || fail NATIVE_ARGON2_INTEGRITY_FAILED
actual=$(sha256sum "$native/libargon2.so") || fail NATIVE_ARGON2_INTEGRITY_FAILED
[ "${actual%% *}" = "$expected" ] || fail NATIVE_ARGON2_INTEGRITY_FAILED
[ ! -e /opt/expertauth/lib/argon2-jvm-2.11.jar ] || fail NATIVE_ARGON2_BUNDLED_LIBRARY_PRESENT
[ -d /opt/expertauth/.native-tmp ] && [ ! -L /opt/expertauth/.native-tmp ] || fail NATIVE_ARGON2_TEMP_DIRECTORY_INVALID
java -Xmx128m --add-opens=java.base/java.lang=ALL-UNNAMED \
    -Djna.library.path="$native" -Djna.tmpdir=/opt/expertauth/.native-tmp \
    -cp '/opt/expertauth/lib/*' "$native/NativeArgon2Check.java" || fail NATIVE_ARGON2_SELF_TEST_FAILED
if [ "${1-}" = --check-native-only ]; then exit 0; fi
[ "${1-}" = java ] || fail NATIVE_ARGON2_START_COMMAND_INVALID
shift
exec java -Djna.library.path="$native" -Djna.tmpdir=/opt/expertauth/.native-tmp "$@"
