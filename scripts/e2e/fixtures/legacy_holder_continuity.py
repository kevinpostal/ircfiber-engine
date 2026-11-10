#!/usr/bin/env python3
"""Old-holder TCP/TLS continuity prerequisite only, never a memory or rollout gate.

Reuse the real memory fixture, physical socket oracle, META proxy and hot swaps.
The default 12 sessions include six TLS sessions; 4..64 may be selected explicitly
with LEGACY_CONTINUITY_SESSIONS. No stationary warm-up or memory soak is claimed.
"""
import asyncio
import json
import os
from pathlib import Path
import sys
import time

from memory_fixture import Fixture
from memory_qualification import (Qualification as MemoryQualification, OLD_HOLDER,
                                  LEGACY_CONTINUITY_PROFILE, require)

SCOPE = "Old-holder TCP+TLS continuity prerequisite only; not full memory, Rollout A, holder working-set or archival B"
SERVICES = ("redis", "mongo", "ircfiber-gateway", "ircfiber-holder", "mock-irc", "egress-a", "ircfiber-engine")


class LegacyContinuityFixture(Fixture):
    async def control(self, command):
        if command.get("action") == "configure":
            require(command.get("profile") == LEGACY_CONTINUITY_PROFILE and command.get("scope") == SCOPE,
                    "small fixture configuration requires the explicit legacy continuity profile and scope")
            networks = command["networks"]
            require(isinstance(networks, dict) and 4 <= len(networks) <= 64
                    and len(set(networks.values())) == len(networks),
                    "legacy continuity requires 4..64 unique network/nick identities")
            self.networks = networks
            # Return the original wire oracle's status; all other actions and all
            # TCP/TLS, PONG, digest and real holder protocol handling are inherited.
            return await super().control(dict(action="status"))
        return await super().control(command)


class LegacyHolderContinuityQualification(MemoryQualification):
    def __init__(self):
        super().__init__(expected_holder_image=OLD_HOLDER, qualification_scope=SCOPE,
                         _profile=LEGACY_CONTINUITY_PROFILE)

    def run(self):
        self.setup()
        self.rpc("load", enabled=True)
        time.sleep(6)
        self.swap("SIGTERM")
        self.swap("SIGKILL")
        engine = self.identity(self.owned("ircfiber-engine"))
        final = self.catch_up()
        require(self.faults == ["SIGTERM", "SIGKILL"], "both engine-only faults must pass")
        require(self.held() == self.held_baseline, "final exact old-holder identity set changed")
        self.assert_protected()
        current = self.owned("ircfiber-engine")
        require(current["State"]["Running"] and self.identity(current) == engine,
                "engine generation changed during final catch-up")
        self.save("final.json", dict(wire=final, held=self.held_baseline, protected=self.protected))
        return dict(state="passed", legacyContinuityQualified=True, faults=self.faults,
                    tlsSessions=sum(s["tls"] for s in final["sessions"]),
                    physicalSessions=len(final["acceptedPhysical"]), warmupSeconds=0, measuredSeconds=0)


def main():
    if sys.argv[1:] == ["serve"]:
        asyncio.run(LegacyContinuityFixture().run())
        return 0
    capture_only = sys.argv[1:] == ["--capture-launcher-failure"]
    qualification = None
    result = dict(state="failed", legacyContinuityQualified=False)
    try:
        require(not sys.argv[1:] or capture_only, "unsupported legacy continuity arguments")
        qualification = LegacyHolderContinuityQualification()
        if capture_only:
            result["reason"] = "owned launcher failed before qualification completed"
            errors = {}
            for service in SERVICES:
                try:
                    qualification.ids[service] = qualification.owned(service)["Id"]
                except Exception as error:
                    errors[service] = str(error)[:500]
            if errors:
                result["unavailableServices"] = errors
        else:
            result = qualification.run()
    except BaseException as error:
        result = dict(state="failed", legacyContinuityQualified=False,
                      reason=(type(error).__name__ + ": " + str(error))[:2000])
    finally:
        if qualification:
            if result["state"] != "passed":
                qualification.capture_failure_evidence(result)
            try:
                qualification.stop_logs()
            except BaseException as error:
                result.update(state="failed", legacyContinuityQualified=False, cleanupError=str(error)[:500])
                qualification.capture_failure_evidence(result)
    result.update(scope=SCOPE, profile=LEGACY_CONTINUITY_PROFILE, qualified=False,
                  rolloutAQualified=False, holderWorkingSetQualified=False, archiveBQualified=False,
                  stationaryMemoryQualified=False,
                  inputImages={k: os.environ.get("ROUTING_REGRESSION_" + k.upper() + "_IMAGE")
                               for k in ("engine", "holder", "gateway")},
                  run=os.environ.get("ROUTING_REGRESSION_RUN"),
                  sessions=qualification.sessions if qualification else None)
    path = os.environ.get("MEMORY_EVIDENCE_DIR")
    if path and Path(path).is_dir():
        (Path(path) / "result.json").write_text(json.dumps(result) + "\n")
    print(json.dumps(result), flush=True)
    return 0 if result["state"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
