#!/usr/bin/env python3
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
"""Execute the built resident payload with simulated LK APIs, never hardware.

Run after make ARCH=arm64. Requires Unicorn, pyelftools and liblk.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UcError)
from unicorn.arm64_const import *

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'utils'))
from patch import DeviceConfig
from patch_arm64 import BASE, STOCK_SHA256, encode_bl, elf_layout


class Machine:
    def __init__(self):
        original = (ROOT.parent / 'lk.img').read_bytes()
        assert hashlib.sha256(original).hexdigest() == STOCK_SHA256
        config = DeviceConfig(ROOT / 'configs/xiaomi/xaga_defconfig')
        self.cfg = {k.removeprefix('CONFIG_'): int(v, 0) for k, v in config.config.items()
                    if v.startswith('0x')}
        with (ROOT / 'kaeru.o').open('rb') as stream:
            elf = ELFFile(stream)
            self.syms = {s.name: s.entry.st_value for s in elf.get_section_by_name('.symtab').iter_symbols()}
        self.dest = BASE + 0xc4000
        self.cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.cpu.mem_map(BASE, 0x200000)
        self.cpu.mem_write(BASE, original[512:0xc3618])
        self.cpu.mem_write(self.dest, (ROOT / 'kaeru').read_bytes())
        bootstrap = (ROOT / 'arch/arm64/bootstrap.bin').read_bytes()
        for marker, value in [(0x1122334455667788, self.dest),
                              (0x2233445566778899, self.dest + self.syms['__rx_end']),
                              (0x33445566778899aa, self.cfg['PLATFORM_INIT_ADDRESS'])]:
            bootstrap = bootstrap.replace(struct.pack('<Q', marker), struct.pack('<Q', value))
        self.bootstrap = BASE + 0x71e2c
        self.cpu.mem_write(self.bootstrap, bootstrap)
        self.leaves = {}
        self.permissions = {}
        self.build_tables()
        self.cpu.mem_map(0x70000000, 0x400000)
        self.cpu.mem_write(0x70000000, b'\xc0\x03\x5f\xd6')
        self.cursor = 0x70010000
        self.env = {}
        self.env_write_status = 0
        self.commands = {}
        self.published = {}
        self.responses = []
        self.usb = []
        self.native_calls = []
        self.output = []
        self.devices = {'logo_a': (0x70001000, bytes(range(256)) * 16)}
        dev = self.devices['logo_a'][0]
        head = self.cfg['BIO_DEVICE_LIST_ADDRESS']
        self.cpu.mem_write(head + 8, struct.pack('<Q', dev))
        self.cpu.mem_write(dev + 8, struct.pack('<Q', head))
        self.cpu.mem_write(dev + 0x20, struct.pack('<Q', 4096))
        self.cpu.mem_write(dev + 0x40, struct.pack('<Q', self.string('logo_a')))
        self.cpu.mem_write(self.cfg['FASTBOOT_TRANSPORT_ADDRESS'], struct.pack('<Q', 0x70002000))
        self.cpu.mem_write(0x70002030, struct.pack('<Q', 0x70003000))
        self.hooks = {
            self.cfg['DPRINTF_ADDRESS']: self.log,
            self.cfg['VIDEO_PRINTF_ADDRESS']: self.log,
            self.cfg['FASTBOOT_REGISTER_ADDRESS']: self.register,
            self.cfg['FASTBOOT_PUBLISH_ADDRESS']: self.publish,
            self.cfg['FASTBOOT_INFO_ADDRESS']: lambda: self.response('INFO'),
            self.cfg['FASTBOOT_OKAY_ADDRESS']: lambda: self.response('OKAY'),
            self.cfg['FASTBOOT_FAIL_ADDRESS']: lambda: self.response('FAIL'),
            self.cfg['GET_ENV_ADDRESS']: self.get_env,
            self.cfg['SET_ENV_ADDRESS']: self.set_env,
            self.cfg['PLATFORM_INIT_ADDRESS']: lambda: self.mark('platform_init'),
            self.cfg['ENV_INIT_ADDRESS']: lambda: self.mark('env_init'),
            self.cfg['APP_ADDRESS']: lambda: self.mark('app_init', self.reg(0)),
            self.cfg['BIO_OPEN_ADDRESS']: self.bio_open,
            self.cfg['BIO_CLOSE_ADDRESS']: lambda: 0,
            self.cfg['BIO_READ_ADDRESS']: self.bio_read,
            self.cfg['BIO_WRITE_ADDRESS']: self.bio_write,
            BASE + 0x6a7c8: self.strcmp,
            0x70003000: self.send,
        }
        self.cpu.hook_add(UC_HOOK_CODE, self.hook)

    def build_tables(self):
        self.next_table = 0x50fd1000
        root = 0x50fd0000
        self.cpu.cpr_write(3, 0, 2, 0, 1, root)  # TTBR1_EL1
        self.cpu.cpr_write(3, 0, 2, 0, 2, 0x2b5103590)  # Native TCR_EL1 configuration
        for va in range(BASE, BASE + 0x200000, 4096):
            table = root
            for shift in (39, 30, 21, 12):
                location = (0xffff000000000000 | table) + ((va >> shift) & 511) * 8
                if shift == 12:
                    # Native text RX, native rodata R-NX, all remaining data RW-NX.
                    attrs = 0x403
                    if va < BASE + 0x83000: attrs |= 128
                    else:
                        attrs |= (1 << 53) | (1 << 54)
                        if va < BASE + 0xb6000: attrs |= 128
                    self.cpu.mem_write(location, struct.pack('<Q', (va & 0x0000fffffffff000) | attrs))
                    self.leaves[va] = location
                else:
                    entry = struct.unpack('<Q', self.cpu.mem_read(location, 8))[0]
                    if entry & 3 != 3:
                        entry = self.next_table | 3
                        self.next_table += 4096
                        self.cpu.mem_write(location, struct.pack('<Q', entry))
                    table = entry & 0x0000fffffffff000
        self.sync_permissions()

    def sync_permissions(self):
        # Apply page protections, including the SCTLR.WXN execution restriction.
        for va, location in self.leaves.items():
            entry = struct.unpack('<Q', self.cpu.mem_read(location, 8))[0]
            readonly = bool(entry & 128)
            flags = UC_PROT_READ | (0 if readonly else UC_PROT_WRITE)
            if readonly and not entry & (1 << 53): flags |= UC_PROT_EXEC
            if self.permissions.get(va) != flags:
                self.cpu.mem_protect(va, 4096, flags)
                self.permissions[va] = flags

    def reg(self, number):
        return self.cpu.reg_read(UC_ARM64_REG_X0 + number)

    def cstring(self, ptr):
        if not ptr: return ''
        out = bytearray()
        for i in range(4096):
            byte = self.cpu.mem_read(ptr + i, 1)[0]
            if not byte: return out.decode('utf8')
            out.append(byte)
        raise AssertionError('unterminated string')

    def alloc(self, data):
        pointer = self.cursor
        self.cpu.mem_write(pointer, data)
        self.cursor = (pointer + len(data) + 15) & ~15
        return pointer

    def string(self, value):
        return self.alloc(value.encode() + b'\0')

    def mark(self, name, *args):
        self.native_calls.append((name, *args))
        return 0

    def log(self):
        text = self.cstring(self.reg(0))
        self.output.append(chr(self.reg(1) & 255) if text == '%c' else text)
        return 1

    def register(self):
        prefix = self.cstring(self.reg(0))
        handler = self.reg(1)
        assert self.dest <= handler < self.dest + self.syms['__image_end']
        self.commands[prefix] = handler
        assert self.reg(3) == 0, 'commands must remain available when spoofing locked'
        return 0

    def publish(self):
        self.published[self.cstring(self.reg(0))] = self.cstring(self.reg(1))
        return 0

    def response(self, status):
        self.responses.append((status, self.cstring(self.reg(0))))
        return 0

    def get_env(self):
        value = self.env.get(self.cstring(self.reg(0)))
        return self.string(value) if value is not None else 0

    def set_env(self):
        if self.env_write_status:
            return self.env_write_status
        self.env[self.cstring(self.reg(0))] = self.cstring(self.reg(1))
        return 0

    def strcmp(self):
        left, right = self.cstring(self.reg(0)), self.cstring(self.reg(1))
        return (left > right) - (left < right)

    def bio_open(self):
        device = self.devices.get(self.cstring(self.reg(0)))
        return device[0] if device else 0

    def bio_read(self):
        dev, destination, offset, count = [self.reg(i) for i in range(4)]
        content = next(data for address, data in self.devices.values()
                       if address == dev)[offset:offset + count]
        self.cpu.mem_write(destination, content)
        return len(content)

    def bio_write(self):
        dev, source, offset, count = [self.reg(i) for i in range(4)]
        name, (_, old) = next((name, device) for name, device in self.devices.items()
                             if device[0] == dev)
        content = bytes(self.cpu.mem_read(source, count))
        self.devices[name] = (dev, old[:offset] + content + old[offset + count:])
        return count

    def add_misc(self, command=b'boot-recovery'):
        content = bytearray((i % 251) + 1 for i in range(8192))
        content[:32] = command.ljust(32, b'\0')
        dev = 0x70004000
        head = self.cfg['BIO_DEVICE_LIST_ADDRESS']
        self.cpu.mem_write(self.devices['logo_a'][0] + 8, struct.pack('<Q', dev))
        self.cpu.mem_write(dev + 8, struct.pack('<Q', head))
        self.cpu.mem_write(dev + 0x20, struct.pack('<Q', len(content)))
        self.cpu.mem_write(dev + 0x40, struct.pack('<Q', self.string('misc')))
        self.devices['misc'] = (dev, bytes(content))
        return bytes(content)

    def send(self):
        pointer, count, timeout = [self.reg(i) for i in range(3)]
        assert timeout == 5000
        self.usb.append(bytes(self.cpu.mem_read(pointer, count)))
        return count

    def hook(self, cpu, pc, size, context):
        instruction = struct.unpack('<I', cpu.mem_read(pc, 4))[0]
        if instruction == 0xd508831f:  # tlbi vmalle1is
            self.sync_permissions()
        fn = self.hooks.get(pc)
        if fn:
            result = fn()
            cpu.reg_write(UC_ARM64_REG_X0, result & 0xffffffffffffffff)
            cpu.reg_write(UC_ARM64_REG_PC, cpu.reg_read(UC_ARM64_REG_X30))

    def run(self, address, *args):
        self.cpu.reg_write(UC_ARM64_REG_SP, 0x703f0000)
        self.cpu.reg_write(UC_ARM64_REG_X30, 0x70000000)
        for i, value in enumerate(args): self.cpu.reg_write(UC_ARM64_REG_X0 + i, value)
        self.cpu.emu_start(address, 0x70000000, count=2000000)
        assert self.cpu.reg_read(UC_ARM64_REG_PC) == 0x70000000, hex(self.cpu.reg_read(UC_ARM64_REG_PC))
        return self.reg(0)

    def function(self, name, *args):
        return self.run(self.dest + self.syms[name], *args)

    def command(self, name, arg='', data=0, size=0):
        self.responses.clear()
        return self.run(self.commands[name], self.string(arg), data, size)

    def boot(self):
        self.run(self.bootstrap)
        self.function('xaga_env_init')
        self.function('kaeru_late_init', 0xffff000050fb5908)


class PortTests(unittest.TestCase):
    def setUp(self):
        self.machine = Machine()

    def test_startup_hooks_and_registration(self):
        m = self.machine
        m.boot()
        self.assertIn(('platform_init',), m.native_calls)
        self.assertIn(('env_init',), m.native_calls)
        self.assertIn(('app_init', 0xffff000050fb5908), m.native_calls)
        app_pointer = struct.unpack('<Q', m.cpu.mem_read(BASE + 0xb5910, 8))[0]
        self.assertEqual(app_pointer, m.dest + m.syms['kaeru_late_init'])
        self.assertEqual(len(m.commands), 9)
        m.command('oem kaeru-status')
        self.assertIn(('INFO', 'environment hook: ran'), m.responses)
        self.assertIn(('INFO', 'late init: ran'), m.responses)
        self.assertEqual(m.run(m.cfg['VFY_POLICY_ADDRESS'], m.string('logo')), 0)

    def test_resident_region_is_nx_before_bootstrap(self):
        with self.assertRaises(UcError):
            self.machine.run(self.machine.dest)

    def test_bootstrap_makes_only_code_rx_and_restores_native_protection(self):
        m = self.machine
        m.boot()
        self.assertEqual(m.permissions[m.dest], UC_PROT_READ | UC_PROT_EXEC)
        self.assertEqual(m.permissions[m.dest + m.syms['__rx_end']], UC_PROT_READ | UC_PROT_WRITE)
        native = m.cfg['GET_LOCK_STATE_ADDRESS'] & ~4095
        self.assertEqual(m.permissions[native], UC_PROT_READ | UC_PROT_EXEC)

    def test_bootstrap_unsupported_translation_layout_falls_back(self):
        m = self.machine
        m.cpu.cpr_write(3, 0, 2, 0, 2, 0)
        m.run(m.bootstrap)
        self.assertEqual(m.native_calls, [('platform_init',)])
        self.assertEqual(m.commands, {})
        self.assertEqual(m.permissions[m.dest], UC_PROT_READ | UC_PROT_WRITE)

    def test_spoof_control_and_recovery_state(self):
        m = self.machine
        m.boot()
        out = m.alloc(bytes(4))
        m.run(m.cfg['GET_LOCK_STATE_ADDRESS'], out)
        self.assertEqual(struct.unpack('<I', m.cpu.mem_read(out, 4))[0], 3)
        m.command('oem bldr_spoof', ' on')
        self.assertEqual(m.responses[-1][0], 'OKAY')
        m.run(m.cfg['GET_LOCK_STATE_ADDRESS'], out)
        self.assertEqual(struct.unpack('<I', m.cpu.mem_read(out, 4))[0], 4)
        m.run(m.cfg['AVB_SET_BOOT_STATE_ADDRESS'], 2)
        state = m.cfg['AVB_BOOT_STATE_ADDRESS']
        self.assertEqual(struct.unpack('<I', m.cpu.mem_read(state, 4))[0], 0)
        m.cpu.mem_write(m.cfg['BOOTMODE_ADDRESS'], struct.pack('<I', 2))
        m.run(m.cfg['AVB_SET_BOOT_STATE_ADDRESS'], 2)
        self.assertEqual(struct.unpack('<I', m.cpu.mem_read(state, 4))[0], 2)
        m.cpu.mem_write(m.cfg['BOOTMODE_ADDRESS'], struct.pack('<I', 99))
        m.run(m.cfg['GET_LOCK_STATE_ADDRESS'], out)
        self.assertEqual(struct.unpack('<I', m.cpu.mem_read(out, 4))[0], 3)
        m.cpu.mem_write(m.cfg['BOOTMODE_ADDRESS'], struct.pack('<I', 0))
        m.command('oem bldr_spoof', ' off')
        m.run(m.cfg['GET_LOCK_STATE_ADDRESS'], out)
        self.assertEqual(struct.unpack('<I', m.cpu.mem_read(out, 4))[0], 3)

    def test_spoof_persistence_failure_is_reported(self):
        m = self.machine
        m.boot()
        m.env_write_status = -1
        m.command('oem bldr_spoof', ' on')
        self.assertEqual(m.responses[-1], ('FAIL', 'Failed to persist bootloader spoof setting'))
        self.assertEqual(m.env, {})

    def test_native_recovery_routing_and_fastboot_key_override(self):
        cases = [
            (b'boot-recovery', (1,), 0, 0, 99),
            (b'boot-recovery', (), 0, 0, 2),
            (b'', (1,), 0, 2, 99),
            (b'', (), 0, 2, 2),
            (b'', (6,), 0, 0, 2),
            (b'', (1,), 2, 0, 99),
            (b'boot-recovery', (1,), 4, 0, 4),
        ]
        for command, keys, preloader, reset, expected in cases:
            with self.subTest(command=command, keys=keys, preloader=preloader, reset=reset):
                m = Machine()
                original = m.add_misc(command)
                m.boot()
                m.env['kaeru_bootloader_spoof_status'] = '1'
                m.cpu.mem_write(m.cfg['BOOTMODE_ADDRESS'], struct.pack('<I', preloader))
                m.hooks[BASE + 0x2b28] = lambda: preloader
                m.hooks[BASE + 0x3b9f0] = lambda: reset
                m.hooks[BASE + 0x2b1c] = lambda: 0
                m.hooks[BASE + 0x1b9f0] = lambda: 0
                m.hooks[BASE + 0x68774] = lambda: m.alloc(bytes(m.reg(0)))
                m.hooks[BASE + 0x688a4] = lambda: 0
                m.hooks[m.cfg['KEY_DETECT_ADDRESS']] = lambda: int(m.reg(0) in keys)
                m.hooks[BASE + 0x29c0] = lambda: 0
                site = m.cfg['BOOT_SELECT_CALLER']
                instruction = struct.unpack('<I', m.cpu.mem_read(site, 4))[0]
                offset = instruction & 0x3ffffff
                if offset & 0x2000000: offset -= 0x4000000
                self.assertEqual(site + offset * 4, m.dest + m.syms['xaga_select_boot_mode'])
                m.run(site + offset * 4)
                self.assertEqual(m.cpu.mem_read(m.cfg['SELECTED_BOOTMODE_ADDRESS'], 1)[0], expected)
                self.assertEqual(m.devices['misc'][1], original)
                if expected in (2, 99):
                    self.assertEqual(struct.unpack('<I', m.cpu.mem_read(m.cfg['BOOTMODE_ADDRESS'], 4))[0], expected)
                if expected == 99:
                    state = m.alloc(bytes(4))
                    m.run(m.cfg['GET_LOCK_STATE_ADDRESS'], state)
                    self.assertEqual(struct.unpack('<I', m.cpu.mem_read(state, 4))[0], 3)
                elif expected == 2:
                    m.run(m.cfg['AVB_SET_BOOT_STATE_ADDRESS'], 2)
                    self.assertEqual(struct.unpack('<I', m.cpu.mem_read(m.cfg['AVB_BOOT_STATE_ADDRESS'], 4))[0], 2)

    def test_cancel_recovery_preserves_other_misc_bytes(self):
        m = self.machine
        original = m.add_misc()
        m.boot()
        m.command('oem cancel-recovery')
        self.assertEqual(m.responses[-1], ('OKAY', ''))
        self.assertEqual(m.devices['misc'][1], bytes(32) + original[32:])

    def test_cancel_recovery_rejects_other_commands_and_arguments(self):
        m = self.machine
        original = m.add_misc(b'boot-fastboot')
        m.boot()
        m.command('oem cancel-recovery')
        self.assertEqual(m.responses[-1][0], 'FAIL')
        self.assertEqual(m.devices['misc'][1], original)
        m.command('oem cancel-recovery', ' unexpected')
        self.assertEqual(m.responses[-1][0], 'FAIL')
        self.assertEqual(m.devices['misc'][1], original)

    def test_cancel_recovery_empty_command_does_not_write(self):
        m = self.machine
        original = m.add_misc(b'')
        m.boot()
        m.hooks[m.cfg['BIO_WRITE_ADDRESS']] = lambda: self.fail('Unexpected write')
        m.command('oem cancel-recovery')
        self.assertEqual(m.responses[-1], ('OKAY', ''))
        self.assertEqual(m.devices['misc'][1], original)

    def test_cancel_recovery_storage_failures_are_reported(self):
        m = self.machine
        original = m.add_misc()
        m.boot()
        read_address, write_address = m.cfg['BIO_READ_ADDRESS'], m.cfg['BIO_WRITE_ADDRESS']
        m.hooks[read_address] = lambda: 32
        m.command('oem cancel-recovery')
        self.assertEqual(m.responses[-1], ('FAIL', 'Failed to read misc'))
        m.hooks[read_address] = m.bio_read
        m.hooks[write_address] = lambda: 512
        m.command('oem cancel-recovery')
        self.assertEqual(m.responses[-1][0], 'FAIL')
        self.assertEqual(m.devices['misc'][1], original)
        m.hooks[write_address] = lambda: m.reg(3)  # pretend success without writing
        m.command('oem cancel-recovery')
        self.assertEqual(m.responses[-1][0], 'FAIL')
        self.assertIn('verification failed', m.responses[-1][1])
        self.assertEqual(m.devices['misc'][1], original)

    def test_native_rollback_read_needs_initialization_before_avb(self):
        m = self.machine
        m.boot()
        # Execute the real LK callback from AvbOps, including its security
        # adapter: without initialization it returns AVB_IO_RESULT_ERROR_IO.
        m.hooks[BASE + 0x7d0e8] = lambda: 0  # native security logging gate
        reads = []

        def read_otp():
            reads.append(m.reg(0))
            m.cpu.mem_write(m.reg(1), struct.pack('<I', 1))
            return 0

        m.hooks[BASE + 0x7a3f8] = read_otp  # only hardware reads are simulated
        out_index = m.alloc(bytes(8))
        callback = BASE + 0x81b9c
        self.assertEqual(m.run(callback, 0, 0, out_index), 2)
        self.assertEqual(bytes(m.cpu.mem_read(out_index, 8)), bytes(8))
        expected = [m.alloc(bytes(16)), m.alloc(bytes(24)), m.string('_a'),
                    1, 4, m.alloc(bytes(8))]
        slot = m.alloc(bytes(0x138))
        calls = []

        def verify():
            calls.append([m.reg(i) for i in range(6)])
            self.assertEqual(bytes(m.cpu.mem_read(0xffff0000510a1b6c, 1)), b'\1')
            m.cpu.mem_write(m.reg(5), struct.pack('<Q', slot))
            return 3  # recoverable verification error must remain visible

        m.hooks[m.cfg['AVB_SLOT_VERIFY_ADDRESS']] = verify
        # Invoke the actual patched BL instruction in native load_vfy_boot.
        site = m.cfg['AVB_SLOT_VERIFY_CALLER']
        instruction = struct.unpack('<I', m.cpu.mem_read(site, 4))[0]
        offset = instruction & 0x3ffffff
        if offset & 0x2000000: offset -= 0x4000000
        self.assertEqual(site + offset * 4, m.dest + m.syms['xaga_avb_slot_verify'])
        self.assertEqual(m.run(site + offset * 4, *expected), 3)
        self.assertEqual(calls, [expected])
        self.assertEqual(struct.unpack('<Q', m.cpu.mem_read(expected[5], 8))[0], slot)
        self.assertTrue(reads)
        # Native group 2 spans two OTP words, each with one bit in this fixture.
        self.assertEqual(m.run(callback, 0, 0, out_index), 0)
        self.assertEqual(struct.unpack('<Q', m.cpu.mem_read(out_index, 8))[0], 2)
        self.assertEqual(m.run(callback, 0, 1, out_index), 0)
        self.assertEqual(struct.unpack('<Q', m.cpu.mem_read(out_index, 8))[0], 2)

    def test_otp_initialization_failure_does_not_call_avb(self):
        m = self.machine
        m.boot()
        m.hooks[BASE + 0x7d0e8] = lambda: 0
        m.hooks[BASE + 0x7a3f8] = lambda: 1
        calls = []
        m.hooks[m.cfg['AVB_SLOT_VERIFY_ADDRESS']] = lambda: calls.append(True) or 0
        out = m.alloc(struct.pack('<Q', 0x1234))
        self.assertEqual(m.function('xaga_avb_slot_verify', 0, 0, 0, 1, 4, out), 2)
        self.assertEqual(bytes(m.cpu.mem_read(out, 8)), bytes(8))
        self.assertEqual(calls, [])

    def test_memory_addresses_keep_upper_bits(self):
        m = self.machine
        m.boot()
        target = 0xffff0000510b0000
        m.cpu.mem_write(target, b'abcdefgh')
        m.command('oem mem', f' read {target:x} 8')
        self.assertEqual(m.responses[-1], ('OKAY', ''))
        self.assertIn('ffff0000510b0000', m.responses[0][1])
        m.command('oem mem', f' write {target:x} 12345678')
        self.assertEqual(bytes(m.cpu.mem_read(target, 4)), bytes.fromhex('78563412'))

    def test_native_storage_fetch_and_getvar_trampoline(self):
        m = self.machine
        m.boot()
        staging = m.alloc(bytes(4096))
        m.command('fetch:', 'logo_a:100:40', staging, 4096)
        self.assertEqual(m.usb[0], b'DATA00000040')
        self.assertEqual(m.usb[1], bytes(range(64)))
        self.assertEqual(m.responses[-1], ('OKAY', ''))
        m.responses.clear()
        m.run(m.cfg['FASTBOOT_GETVAR_ADDRESS'], m.string('max-fetch-size'), staging, 0)
        self.assertEqual(m.responses[-1], ('OKAY', '0x100000'))
        m.responses.clear()
        m.run(m.cfg['FASTBOOT_GETVAR_ADDRESS'], m.string('unknown-test-variable'), staging, 0)
        self.assertEqual(m.responses[-1], ('OKAY', ''))
        m.command('fetch:', 'logo_a:fff:2', staging, 4096)
        self.assertEqual(m.responses[-1], ('FAIL', 'Requested range is outside the partition'))


class BuilderTests(unittest.TestCase):
    def test_branch_encoding_rejects_bad_targets(self):
        self.assertEqual(struct.unpack('<I', encode_bl(BASE, BASE + 4))[0], 0x94000001)
        for target in (BASE + 1, BASE + 0x8000000, BASE - 0x8000004):
            with self.assertRaises(ValueError): encode_bl(BASE, target)

    def test_layout_matches_raw_payload(self):
        payload = (ROOT / 'kaeru').read_bytes()
        symbols, count = elf_layout(ROOT / 'kaeru.o', payload)
        self.assertGreater(count, 0)
        self.assertGreater(symbols['__image_end'], len(payload))
        self.assertLess(BASE + 0xc4000 + symbols['__image_end'], 0xffff000050ff2000)
        with self.assertRaises(ValueError):
            elf_layout(ROOT / 'kaeru.o', payload[:-1])

    def test_container_roundtrip_and_wrong_input_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            output = directory / 'candidate.img'
            command = [sys.executable, str(ROOT / 'utils/patch_arm64.py'),
                       str(ROOT / 'configs/xiaomi/xaga_defconfig'),
                       str(ROOT.parent / 'lk.img'), str(ROOT / 'kaeru'),
                       '--elf', str(ROOT / 'kaeru.o'), '-o', str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(output.with_suffix('.img.json').read_text())
            self.assertTrue(manifest['payload_page_aligned'])
            self.assertEqual(manifest['unchanged_subpartitions'], ['bl2_ext', 'aee', 'lk_main_dtb'])
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), manifest['output_sha256'])
            changed = bytearray((ROOT.parent / 'lk.img').read_bytes())
            changed[0x200] ^= 1
            invalid_input = directory / 'different-lk.img'
            invalid_input.write_bytes(changed)
            command[3] = str(invalid_input)
            rejected_output = directory / 'rejected.img'
            command[-1] = str(rejected_output)
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('does not match the supported stock xaga LK SHA-256', result.stderr)
            self.assertFalse(rejected_output.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
