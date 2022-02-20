#!/usr/bin/env python3

import argparse
import sys
import os.path


class KSWFirmwareBin:
    '''
    KSW firmware update file tool

    Can check, display, and re-sign firmware .bin files.
    '''

    NEW_FILE_ID = bytes.fromhex('FFFFFFFFAAF055A500AA')
    CHECK_CODES = {
        'JLY_CIC_1280_480_JLY-CIC-GTL': bytes.fromhex('01207763786c036f0210'),
        'JLY_CCC_1920x720_JLY-CCC-GTL-DC': bytes.fromhex('01207a66796e04700210'),
        'dGS_._1280_480_dGS-.-GT.': bytes.fromhex('023052014d01570101a0'),
        'dGS_._1920_720_dGS-.-.T.-DC': bytes.fromhex('0230550450045a0201a0'),
        'dLS_CIC_1920_720_dLS-CIC-GTL-DC': bytes.fromhex('1052450360065a062501'),
        'LZH_._1280_480_LZH-.-GT.': bytes.fromhex('415187626b6603a11514'),
        'ALS_._1280_480_dALS-.-GT.': bytes.fromhex('615054044d0257020516'),
        'ALS_NBT_EVO_1280_480_dALS-ID.-.-GT': bytes.fromhex('615065055d0358010516'),
        'ALS_._1920_720_dALS-.-GT.-DC': bytes.fromhex('615095085d0359010516'),
        'ALS_NBT_EVO_1920_720_dALS-ID.-.-GT-DC': bytes.fromhex('615096095e045a020516'),
        'ALS_CIC_1920_720_eALS-CIC-TL-DC': bytes.fromhex('6150a0fae049387216fa')
    }
    BASE_ADDR = 0x08002800
    FW_STRING_ADDR = 0x08004800 - BASE_ADDR
    FW_STRING_LEN = 28
    FW_STRING_SLICE = slice(FW_STRING_ADDR, FW_STRING_ADDR+FW_STRING_LEN)
    ID_SLICE = slice(-24, -14)
    CSUM_SLICE = slice(-14, -10)
    CHECK_SLICE = slice(-10, None)

    def __init__(self, file) -> None:
        self.data = bytearray(file.read())
        self.file_id = self.data[KSWFirmwareBin.ID_SLICE]
        self.file_csum = int.from_bytes(self.data[KSWFirmwareBin.CSUM_SLICE], 'big')
        self.file_check = self.data[KSWFirmwareBin.CHECK_SLICE]
        self.file_str = self.data[KSWFirmwareBin.FW_STRING_SLICE].decode('utf-8').strip('\0')

    def write(self, file):
        file.write(self.data)

    def print_info(self):
        ccode = 'UNKNOWN!'
        for c in KSWFirmwareBin.CHECK_CODES:
            if KSWFirmwareBin.CHECK_CODES[c] == self.file_check:
                ccode = c

        is_new = self.file_id == KSWFirmwareBin.NEW_FILE_ID

        csum = self.calc_checksum()
        csum_ok = self.file_csum == csum

        print(f'Total Length:        {len(self.data):08x} ({len(self.data)})\n'
              f'FW Length:           {len(self.data)-24:08x} ({len(self.data)-24})\n'
              f'File Checksum:       {self.file_csum:08x}\n'
              f'Calculated Checksum: {csum:08x} ({"OK" if csum_ok else "FAILED"})\n'
              f'File Check Code:     {self.file_check.hex()} ({ccode})\n'
              f'File FW String:      {self.file_str}\n'
              f'File Type:           {self.file_id.hex()} {"(NEW)" if is_new else ""}\n'
              f'Update Msg Checksum: {self.calc_checksum(len(self.data)):08x}\n')

    @classmethod
    def print_codes(cls):
        print('Known check codes (. replaces any letter, like C.C for CIC/CCC or GT. for GTH/GTL:\n')
        for c in KSWFirmwareBin.CHECK_CODES:
            print(c)
        print('\nUse with caution, flashing a wrong image to a device can make it unusable and hard to recover!\n')

    def calc_checksum(self, limit=None):
        limit = limit or len(self.data) - 24
        csum = 0
        for b in self.data[:limit]:
            csum = (csum + b) % 0x100000000
        return csum

    def update_checksum(self):
        self.file_csum = self.calc_checksum()
        self.data[KSWFirmwareBin.CSUM_SLICE] = self.file_csum.to_bytes(4, 'big')

    def change_check(self, new_code_id):
        if new_code_id not in KSWFirmwareBin.CHECK_CODES:
            print(f'Check Code "{new_code_id}" is unknown.')
            self.print_codes()
            sys.exit(-1)
        self.file_check = KSWFirmwareBin.CHECK_CODES[new_code_id]
        self.data[KSWFirmwareBin.ID_SLICE] = KSWFirmwareBin.CHECK_CODES[new_code_id]

    def change_id(self, new_id):
        if len(new_id) > 27:
            print(f'FW ID "{new_id}" is too long. Maximum is 27.')
            self.print_codes()
            sys.exit(-1)
        self.file_str = new_id
        self.data[KSWFirmwareBin.FW_STRING_SLICE] = self.file_str.encode(
            'utf-8').ljust(KSWFirmwareBin.FW_STRING_LEN, b'\0')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=KSWFirmwareBin.__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-f', '--fw', default='ksw_mcu.bin', help='firmware file (input), in bin format')
    parser.add_argument('-u', '--update_checksum', action='store_true',
                        help='update the file checksum to match content')
    parser.add_argument('-c', '--change_check', nargs=1, metavar='CODE',
                        help='update the file check code to change manufacturer/device type. BE CAREFUL!')
    parser.add_argument('-i', '--change_id', nargs=1, metavar='ID',
                        help='update the FW string to change manufacturer/device type. BE CAREFUL!')
    parser.add_argument('-o', '--output', help='output file to write to')
    parser.add_argument('--print_codes', action='store_true',
                        help='output the list of known check codes')

    args = parser.parse_args()

    if args.print_codes:
        KSWFirmwareBin.print_codes()
        sys.exit(0)

    if not os.path.exists(args.fw):
        parser.print_help()
        print(f'\nFirmware file {args.fw} not found. Exiting...')
        sys.exit(-1)

    with open(args.fw, 'rb') as in_bin:
        ksw_bin = KSWFirmwareBin(in_bin)

    ksw_bin.print_info()

    changed = False

    if args.change_check:
        ksw_bin.change_check(args.change_check[0])
        changed = True

    if args.change_id:
        ksw_bin.change_id(args.change_id[0])
        changed = True

    if args.update_checksum:
        ksw_bin.update_checksum()
        changed = True

    if changed:
        print('\nFile information after changes:')
        ksw_bin.print_info()
        if not args.output:
            print('\nNo output file specified, not writing modified binary!')
        else:
            with open(args.output, 'wb') as out_bin:
                ksw_bin.write(out_bin)
            print(f'Output written to {args.output}')
