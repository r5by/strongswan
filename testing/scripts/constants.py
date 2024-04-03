# sudo cp /home/xad/code/strongswan/testing/scripts/constants.py  ~/strongswan-testing/build/linux-6.3.6/scripts/gdb/linux/constants.py
import gdb
LX_CONFIG_DEBUG_INFO_REDUCED
if 1:
    LX_CLK_GET_RATE_NOCACHE = gdb.parse_and_eval("((((1UL))) << (6))")
LX_SB_RDONLY = gdb.parse_and_eval("((((1UL))) << (0))")
LX_SB_SYNCHRONOUS = gdb.parse_and_eval("((((1UL))) << (4))")
LX_SB_MANDLOCK = gdb.parse_and_eval("((((1UL))) << (6))")
LX_SB_DIRSYNC = gdb.parse_and_eval("((((1UL))) << (7))")
LX_SB_NOATIME = gdb.parse_and_eval("((((1UL))) << (10))")
LX_SB_NODIRATIME = gdb.parse_and_eval("((((1UL))) << (11))")
LX_hrtimer_resolution = gdb.parse_and_eval("hrtimer_resolution")
LX_MNT_NOSUID = 0x01
LX_MNT_NODEV = 0x02
LX_MNT_NOEXEC = 0x04
LX_MNT_NOATIME = 0x08
LX_MNT_NODIRATIME = 0x10
LX_MNT_RELATIME = 0x20
LX_NR_CPUS = 1
LX_OF_DT_HEADER = 0xd00dfeed
LX_CONFIG_GENERIC_CLOCKEVENTS = 1
LX_CONFIG_GENERIC_CLOCKEVENTS_BROADCAST = 1
LX_CONFIG_HIGH_RES_TIMERS = 1
LX_CONFIG_NR_CPUS = 1
LX_CONFIG_OF = 0
LX_CONFIG_TICK_ONESHOT = 1