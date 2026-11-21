"""Minimal Mach-O reader: CPU architectures and code-signature Team ID.

Only headers and the embedded signature are parsed. The values pre-fill the catalogue form;
the endpoint enforces the real signature with ``codesign`` / ``spctl`` at install time.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from app.catalogue.inspect.certs import Signer, signer_from_cms
from app.catalogue.inspect.result import TEAM_ID_RE

CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C
_FAT_MAGIC = 0xCAFEBABE
_FAT_MAGIC_64 = 0xCAFEBABF
_MH_MAGIC_64 = 0xFEEDFACF
_LC_CODE_SIGNATURE = 0x1D
_CSMAGIC_EMBEDDED = 0xFADE0CC0
_CSMAGIC_CODEDIRECTORY = 0xFADE0C02
_CSMAGIC_BLOBWRAPPER = 0xFADE0B01
_CS_ADHOC = 0x2
_MAX_SLICES = 8


@dataclass(frozen=True, slots=True)
class MachOInfo:
    architectures: frozenset[str]
    team_id: str | None
    adhoc: bool
    signer: Signer | None

    @property
    def architecture(self) -> str | None:
        if {"x86_64", "arm64"} <= self.architectures:
            return "universal"
        if self.architectures == {"arm64"}:
            return "arm64"
        if self.architectures == {"x86_64"}:
            return "x86_64"
        return None


def _arch_name(cputype: int) -> str | None:
    return {CPU_X86_64: "x86_64", CPU_ARM64: "arm64"}.get(cputype)


def parse_macho(data: bytes) -> MachOInfo | None:
    if len(data) < 32:
        return None
    (magic_be,) = struct.unpack_from(">I", data, 0)
    slices: list[tuple[int, int]] = []
    archs: set[str] = set()
    if magic_be in (_FAT_MAGIC, _FAT_MAGIC_64):
        (count,) = struct.unpack_from(">I", data, 4)
        if count == 0 or count > _MAX_SLICES:
            return None
        entry = 32 if magic_be == _FAT_MAGIC_64 else 20
        for i in range(count):
            base = 8 + i * entry
            if base + entry > len(data):
                return None
            if magic_be == _FAT_MAGIC_64:
                cputype, _sub, offset, size = struct.unpack_from(">iiQQ", data, base)
            else:
                cputype, _sub, offset, size = struct.unpack_from(">iiII", data, base)
            name = _arch_name(cputype & 0xFFFFFFFF)
            if name:
                archs.add(name)
            slices.append((offset, size))
    else:
        slices.append((0, len(data)))

    team: str | None = None
    adhoc = False
    signer: Signer | None = None
    for offset, size in slices:
        if offset + size > len(data) or size < 32:
            continue
        info = _thin(data[offset : offset + size])
        if info is None:
            continue
        arch, slice_team, slice_adhoc, slice_signer = info
        if arch:
            archs.add(arch)
        team = team or slice_team
        adhoc = adhoc or slice_adhoc
        signer = signer or slice_signer
    if not archs:
        return None
    return MachOInfo(frozenset(archs), team, adhoc, signer)


def _thin(data: bytes) -> tuple[str | None, str | None, bool, Signer | None] | None:
    (magic,) = struct.unpack_from("<I", data, 0)
    if magic != _MH_MAGIC_64:
        return None
    cputype, _sub, _ftype, ncmds, sizeofcmds = struct.unpack_from("<iiIII", data, 4)
    arch = _arch_name(cputype & 0xFFFFFFFF)
    cursor = 32
    end = min(len(data), 32 + sizeofcmds)
    for _ in range(min(ncmds, 4096)):
        if cursor + 8 > end:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8:
            break
        if cmd == _LC_CODE_SIGNATURE and cursor + 16 <= end:
            dataoff, datasize = struct.unpack_from("<II", data, cursor + 8)
            team, adhoc, signer = _signature(data, dataoff, datasize)
            return arch, team, adhoc, signer
        cursor += cmdsize
    return arch, None, False, None


def _signature(data: bytes, offset: int, size: int) -> tuple[str | None, bool, Signer | None]:
    if offset + size > len(data) or size < 12:
        return None, False, None
    blob = data[offset : offset + size]
    magic, _length, count = struct.unpack_from(">III", blob, 0)
    if magic != _CSMAGIC_EMBEDDED or count > 64:
        return None, False, None
    team: str | None = None
    adhoc = False
    signer: Signer | None = None
    for i in range(count):
        idx = 12 + i * 8
        if idx + 8 > len(blob):
            break
        _slot, sub_off = struct.unpack_from(">II", blob, idx)
        if sub_off + 8 > len(blob):
            continue
        sub_magic, sub_len = struct.unpack_from(">II", blob, sub_off)
        sub = blob[sub_off : sub_off + sub_len]
        if sub_magic == _CSMAGIC_CODEDIRECTORY and len(sub) >= 52:
            version, flags = struct.unpack_from(">II", sub, 8)
            adhoc = adhoc or bool(flags & _CS_ADHOC)
            if version >= 0x20200 and team is None:
                (team_off,) = struct.unpack_from(">I", sub, 48)
                if 0 < team_off < len(sub):
                    raw = sub[team_off : team_off + 32].split(b"\x00", 1)[0]
                    text = raw.decode("ascii", "replace")
                    team = text if TEAM_ID_RE.fullmatch(text) else None
        elif sub_magic == _CSMAGIC_BLOBWRAPPER and len(sub) > 8 and signer is None:
            signer = signer_from_cms(sub[8:])
    return team, adhoc, signer
