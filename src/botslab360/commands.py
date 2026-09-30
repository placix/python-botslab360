"""Verified read-write command definitions for Botslab/360 robots."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """Wire-level definition of one robot command."""

    info_type: str
    data: str
    requires_task_id: bool = True


START_CLEANING = CommandSpec(
    info_type="21005",
    data='{"mode":"smartClean","globalCleanTimes":1}',
)
PAUSE = CommandSpec(info_type="21017", data='{"cmd":"pause"}')
RESUME = CommandSpec(info_type="21017", data='{"cmd":"continue"}')
RETURN_TO_DOCK = CommandSpec(info_type="21012", data='{"cmd":"start"}')
LOCATE = CommandSpec(
    info_type="21020",
    data='{"ctrlCode":3010}',
    requires_task_id=False,
)
MOP_ONLY_OFF = CommandSpec(
    info_type="21024",
    data='{"cmd":"setMopSwitch","value":1}',
)
MOP_ONLY_ON = CommandSpec(
    info_type="21024",
    data='{"cmd":"setMopSwitch","value":2}',
)
