#!/usr/bin/env python3
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
"""Build a resident AArch64 kaeru image for the supported stock xaga LK."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elftools.elf.elffile import ELFFile
from liblk import LkImage
from patch import DeviceConfig, CERT_BYPASS_BUILDERS

STOCK_SHA256 = 'd9ec458862c71489a84b7f08ba19b8b5f1747b3a36749b99cd71d0badd37b858'
BASE = 0xffff000050f00000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encode_bl(site, target):
    offset = target - site
    require(not (site | target) & 3, 'AArch64 branch addresses must be aligned')
    require(-0x8000000 <= offset < 0x8000000, 'AArch64 branch out of range')
    return struct.pack('<I', 0x94000000 | ((offset >> 2) & 0x3ffffff))


def elf_layout(path, payload):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        require(elf.elfclass == 64 and elf.little_endian and
                elf.header.e_machine == 'EM_AARCH64' and elf.header.e_type == 'ET_DYN',
                'Payload must be an AArch64 PIE ELF')
        require(elf.header.e_entry == 0, 'Resident startup must begin at offset zero')
        symbols = {s.name: s.entry.st_value for s in elf.get_section_by_name('.symtab').iter_symbols()}
        require(symbols['__image_file_end'] == len(payload), 'ELF/raw payload mismatch')
        rela = elf.get_section_by_name('.rela.dyn')
        require(symbols['__rela_start'] == rela.header.sh_addr and
                symbols['__rela_end'] == rela.header.sh_addr + rela.header.sh_size,
                'Relocation bounds do not cover the emitted RELA section')
        relocations = list(rela.iter_relocations())
        for r in relocations:
            require(r.entry.r_info_type == 1027 and r.entry.r_info_sym == 0,
                    'Only R_AARCH64_RELATIVE relocations are supported')
            require(0 <= r.entry.r_offset <= len(payload) - 8, 'Relocation destination out of bounds')
            require(r.entry.r_offset >= symbols['__rx_end'],
                    'Relocation would write into read-only payload code')
            require(0 <= r.entry.r_addend < symbols['__image_end'], 'Relocation addend out of bounds')
        require(symbols['main'] == 0, 'main must have link address zero')
        return symbols, len(relocations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('input', type=Path)
    parser.add_argument('payload', type=Path)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'arch/arm64/bootstrap.bin')
    parser.add_argument('--cert-mode', choices=tuple(CERT_BYPASS_BUILDERS), default='override')
    parser.add_argument('-o', '--output', type=Path, required=True)
    args = parser.parse_args()
    original = args.input.read_bytes()
    require(hashlib.sha256(original).hexdigest() == STOCK_SHA256,
            'Input does not match the supported stock xaga LK SHA-256')
    require(args.input.resolve() != args.output.resolve(), 'Never overwrite the stock input')
    config = DeviceConfig(args.config)
    require(config.get('ARCH_ARM64') == 'y' and config.get('XIAOMI_XAGA') == 'y',
            'Use the xaga AArch64 configuration')
    payload = args.payload.read_bytes()
    symbols, relocations = elf_layout(args.elf, payload)
    lk = LkImage(args.input)
    part = lk.partitions['lk']
    require(part.lk_address == BASE and len(part.data) == 0xc3418, 'Unexpected LK layout')
    data = bytearray(part.data)
    # Native BSS address from the stock AArch64 startup.
    bss = struct.unpack_from('<Q', original, 0x528)[0]
    require(bss == 0xffff000050ff2000, 'Unexpected native BSS start')
    # ADRP in the PIE assumes the load base has the same page offset as VMA 0.
    offset = (len(data) + 4095) & ~4095
    destination = BASE + offset
    require(destination + symbols['__image_end'] <= bss,
            'Resident image/BSS would overlap native LK BSS')
    require(destination + symbols['__image_end'] <= 0xffff000050fd0000,
            'Resident image would overlap the native TTBR1 page-table storage')
    require(symbols['__rx_end'] % 4096 == 0 and symbols['__rx_end'] <= symbols['__image_file_end'],
            'RX/data boundary must be page-aligned')
    site = int(config.get('PLATFORM_INIT_CALLER'), 0)
    expected_target = int(config.get('PLATFORM_INIT_ADDRESS'), 0)
    site_offset = site - BASE
    word = struct.unpack_from('<I', data, site_offset)[0]
    require(word >> 26 == 0x25, 'Platform hook is not an AArch64 BL')
    immediate = word & 0x3ffffff
    if immediate & 0x2000000: immediate -= 0x4000000
    require(site + immediate * 4 == expected_target, 'Original platform_init call mismatch')
    data.extend(bytes(offset - len(data)))
    data.extend(payload)
    data.extend(bytes(symbols['__image_end'] - len(payload)))
    data.extend(bytes((-len(data)) % 16))
    bootstrap = args.bootstrap.read_bytes()
    require(len(bootstrap) <= 0xe8, 'Permission bootstrap exceeds the dead policy function body')
    for marker, value in [(0x1122334455667788, destination),
                          (0x2233445566778899, destination + symbols['__rx_end']),
                          (0x33445566778899aa, expected_target)]:
        sentinel = struct.pack('<Q', marker)
        require(bootstrap.count(sentinel) == 1, 'Permission bootstrap literal missing or duplicated')
        bootstrap = bootstrap.replace(sentinel, struct.pack('<Q', value))
    # get_vfy_policy is deliberately bypassed; reuse its now-dead RX body.
    policy_offset = 0x7201c - 0x200
    data[policy_offset:policy_offset + 8] = struct.pack('<II', 0x52800000, 0xd65f03c0)
    bootstrap_offset = 0x7202c - 0x200
    data[bootstrap_offset:bootstrap_offset + len(bootstrap)] = bootstrap
    data[site_offset:site_offset + 4] = encode_bl(site, BASE + bootstrap_offset)
    # Do not move any native globals, modify BSS clearing, or alter other stages.
    part.data = bytes(data)
    original_cert2 = bytes(part.cert2.data)
    header_hash, image_hash = part.compute_hashes()
    part.cert2.data = CERT_BYPASS_BUILDERS[args.cert_mode](original_cert2, header_hash, image_hash)
    lk._rebuild_contents()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    lk.save(args.output)
    reparsed = LkImage(args.output)
    pristine = LkImage(args.input)
    for name, unchanged in pristine.partitions.items():
        other = reparsed.partitions[name]
        if name == 'lk':
            require(bytes(other.cert1.data) == bytes(unchanged.cert1.data), 'cert1 changed')
            require(bytes(other.data) == bytes(data), 'Patched LK did not round-trip')
            continue
        require(bytes(other.data) == bytes(unchanged.data) and
                bytes(other.header) == bytes(unchanged.header) and
                bytes(other.cert1.data) == bytes(unchanged.cert1.data) and
                bytes(other.cert2.data) == bytes(unchanged.cert2.data),
                'Unintended modification to ' + name)
    if args.cert_mode == 'override':
        # Validate the exact constructed structure, not a claim of OEM signing.
        from pyasn1.codec.der.decoder import decode
        encoded = bytes(reparsed.partitions['lk'].cert2.data)
        require(encoded[:2] == b'\xa0\x58', 'Unexpected override block layout')
        # The vendor context block holds multiple children; decode its contents
        # as a SEQUENCE because schema-free ASN.1 treats [0] as an explicit tag.
        override, unused = decode(b'\x30' + encoded[1:90])
        require(not unused, 'Unexpected bytes inside override block')
        trailing = encoded[90:]
        require(trailing == original_cert2, 'Original signed certificate was not preserved')
        require(bytes(override[1].asOctets()) == header_hash and
                bytes(override[3].asOctets()) == image_hash,
                'Override hashes do not match the packaged image')
    manifest = {
        'status': 'xaga AArch64 port',
        'input_sha256': STOCK_SHA256,
        'output_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
        'payload_sha256': hashlib.sha256(payload).hexdigest(),
        'architecture': 'AArch64',
        'injection': 'resident in the gap preceding native BSS; original BSS addresses preserved',
        'destination': hex(destination), 'payload_file_size': len(payload),
        'payload_memory_size': symbols['__image_end'], 'relative_relocations': relocations,
        'payload_page_aligned': True,
        'permission_bootstrap': hex(BASE + bootstrap_offset),
        'permission_bootstrap_bytes': len(bootstrap),
        'payload_rx_end': hex(destination + symbols['__rx_end']),
        'wxn': 'preserved; payload code RX, relocation/data/BSS RW-NX',
        'native_bss_start': hex(bss), 'platform_call_site': hex(site),
        'cert_mode': args.cert_mode, 'output_bytes': args.output.stat().st_size,
        'unchanged_subpartitions': ['bl2_ext', 'aee', 'lk_main_dtb'],
        'logo': 'not modified',
        'certificate': 'original signed cert2 preserved behind upstream bypass wrapper; no new signature',
        'features': ['fastboot help/version/status', '64-bit memory read and 32-bit word write',
                     'environment get/set', 'native BIO partition listing/read/write API',
                     'fastboot fetch', 'environment-controlled lock-state spoofing',
                     'recovery retains orange AVB state', 'LK verification policy bypass',
                     'native OTP version table initialization before AVB; actual AVB result logging',
                     'fastboot key overrides recovery requests',
                     'explicit recovery request cancellation with readback verification',
                     'dm-verity corruption prompt removal', 'thread API bindings'],
    }
    args.output.with_suffix(args.output.suffix + '.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
