#!/bin/sh

# fix using config
uci -S -c /etc/config batch -f /lib/okos/okos_uci_defcfg_fixup_cmd

# fix stored defcfg
uci -S -c /etc/defcfg batch -f /lib/okos/okos_uci_defcfg_fixup_cmd
