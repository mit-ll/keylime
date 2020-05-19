#!/usr/bin/env python

'''
SPDX-License-Identifier: BSD Clause 2
Copyright 2017 Massachusetts Institute of Technology.
'''

import time
import os

import keylime.tornado_requests as tornado_requests
import keylime.ca_util as ca_util
import keylime.secure_mount as secure_mount
import keylime.common as common
import keylime.keylime_logging as keylime_logging

# read the config file
config = common.get_config()
logger = keylime_logging.init_logging('update_crl')


def execute(json_revocation):
    if json_revocation['type']!='revocation':
        return

    secdir = secure_mount.mount()

    cert_path = config.get('cloud_agent','revocation_cert')
    if cert_path == "default":
        cert_path = '%s/unzipped/RevocationNotifier-cert.crt'%(secdir)
    else:
        # if it is a relative, convert to absolute in work_dir
        if cert_path[0]!='/':
            cert_path = os.path.abspath('%s/%s'%(common.WORK_DIR,cert_path))
        if not os.path.exists(cert_path):
            raise Exception("revocation_cert %s not found"%(os.path.abspath(cert_path)))

    # get the updated CRL
    dist_path = ca_util.get_crl_distpoint(cert_path)


    with open("%s/unzipped/cacrl.der"%(secdir),"rb") as f:
        oldcrl = f.read()

    updated = False
    for i in range(10):
        logger.debug("Getting updated CRL from %s"%dist_path)
        response = tornado_requests.request("GET", dist_path, None, None, None)
        if response.status_code !=200:
            logger.warn("Unable to get updated CRL from %s.  Code %d"%(dist_path,response.status_code))
            time.sleep(1)
            continue
        if response.body == oldcrl:
            logger.warn("CRL not yet updated, trying again in 1 second...")
            time.sleep(1)
            continue

        # write out the updated CRL
        logger.debug("Updating CRL in %s/unzipped/cacrl.der"%(secdir))
        with open("%s/unzipped/cacrl.der"%(secdir),"w") as f:
            f.write(response.body)
        ca_util.convert_crl_to_pem("%s/unzipped/cacrl.der"%(secdir), "%s/unzipped/cacrl.pem"%secdir)
        updated = True
        break

    if not updated:
        logger.error("Unable to load new CRL from %s after receiving notice of a revocation"%dist_path)
