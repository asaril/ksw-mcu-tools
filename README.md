# ksw-mcu-tools
Various tools to work on/with Android head unit MCU firmware.
Compatible with devices running KSW Android software and MCU firmware.

Tested with Android 10, BMW dGS CIC 1280 only, but should work on others unless stated.


## fwtool.py

fwtool.py can be used to check or modify .bin signature information.
The primary purpose is to check and recalculate the file checksum to allow uploading modified files.

Typical usages:

- Show information: `fwtool.py -f ksw_mcu.bin`
- Recalculate the file checksum: `fwtool.py -f ksw_mcu_modified.bin -o ksw_mcu_newcsum.bin -u`

See other options with `-h`.
