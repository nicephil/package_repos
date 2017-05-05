#!/bin/sh

# fix using config
uci -c /etc/config -f /lib/okos/uci_defconfig_fixup_cmd

# fix stored defcfg
uci -c /etc/defcfg -f /lib/okos/uci_defconfig_fixup_cmd
