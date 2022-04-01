#!/bin/bash
################################################################################
# SPDX-License-Identifier: Apache-2.0
# Copyright 2017 Massachusetts Institute of Technology.
################################################################################

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

if [[ -n `systemctl 2>&1 > /dev/null` ]]; then
	echo "No systemd on this system! Will not install emulator services"
	exit 1
fi

cp tpm2-abrmd-emulator.conf /etc/dbus-1/system.d/tpm2-abrmd-emulator.conf

systemctl daemon-reload
systemctl reload dbus.service

# create services and socket
for service in "tpm_emulator.service" "tpm_emulator_rm.service" "ima_emulator.service"; do
  cp  ${service} /etc/systemd/system
  chmod 644 /etc/systemd/system/${service}
  systemctl enable ${service}
done

systemctl daemon-reload
systemctl start ima_emulator.service
