#!/usr/bin/python3

# wget  --ca-certificate=/var/lib/keylime/secure/unzipped/cacert.crt --post-data '{}'
#       --certificate=/var/lib/keylime/secure/unzipped/d432fbb3-d2f1-4a97-9ef7-75bd81c00000-cert.crt
#       --private-key=/var/lib/keylime/secure/unzipped/d432fbb3-d2f1-4a97-9ef7-75bd81c00000-private.pem
#        https://localhost:6892/agents/d432fbb3-d2f1-4a97-9ef7-75bd81c00000

import argparse
import functools
import getpass
import os
import ssl
import sys
import threading
import traceback

import ca_util
import common
import keylime_logging
import tornado.ioloop
import tornado.web
from tornado import httpserver

import keylime.web_util
from keylime import json

sys.path.insert(0, "../../keylime/")

logger = keylime_logging.init_logging("agent_monitor")

INIT_SCRIPT = None


class BaseHandler(tornado.web.RequestHandler):
    def write_error(self, status_code, **kwargs):
        self.set_header("Content-Type", "text/json")
        if self.settings.get("serve_traceback") and "exc_info" in kwargs:
            # in debug mode, try to send a traceback
            lines = []
            for line in traceback.format_exception(*kwargs["exc_info"]):
                lines.append(line)
            self.finish(
                json.dumps(
                    {
                        "code": status_code,
                        "status": self._reason,
                        "traceback": lines,
                        "results": {},
                    }
                )
            )
        else:
            self.finish(
                json.dumps(
                    {
                        "code": status_code,
                        "status": self._reason,
                        "results": {},
                    }
                )
            )


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        keylime.web_util.echo_json_response(self, 405, "Not Implemented: Use /agents/ interface instead")


class AgentsHandler(BaseHandler):
    def head(self):
        """HEAD not supported"""
        keylime.web_util.echo_json_response(self, 405, "HEAD not supported")

    def get(self):
        """This method handles the GET requests to retrieve status on agents from the Agent Monitor.

        Currently, only agents resources are available for GETing, i.e. /agents. All other GET uri's
        will return errors. agents requests require a single agent_id parameter which identifies the
        agent to be returned. If the agent_id is not found, a 404 response is returned.  If the agent_id
        was not found, it either completed successfully, or failed.  If found, the agent_id is still polling
        to contact the Cloud Agent.
        """
        keylime.web_util.echo_json_response(self, 405, "GET not supported")

    def delete(self):
        """This method handles the DELETE requests to remove agents from the Agent Monitor.

        Currently, only agents resources are available for DELETEing, i.e. /agents. All other DELETE uri's will return errors.
        agents requests require a single agent_id parameter which identifies the agent to be deleted.
        """
        keylime.web_util.echo_json_response(self, 405, "DELETE not supported")

    def post(self):
        """This method handles the POST requests to add agents to the Agent Monitor.

        Currently, only agents resources are available for POSTing, i.e. /agents. All other POST uri's will return errors.
        agents requests require a json block sent in the body
        """
        logger.info("Agent Monitor POST")
        try:
            rest_params = keylime.web_util.get_restful_params(self.request.path)

            if "agents" not in rest_params:
                keylime.web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported: " + self.request.path)
                return

            agent_id = rest_params["agents"]

            if agent_id is not None:  # we have to know who phoned home
                content_length = len(self.request.body)
                if content_length == 0:
                    keylime.web_util.echo_json_response(self, 400, "Expected non zero content length")
                    logger.warning("POST returning 400 response. Expected non zero content length.")
                else:
                    json_body = json.loads(self.request.body)

                    # VERIFY CLIENT CERT ID MATCHES AGENT ID (agent_id)
                    client_cert = self.request.get_ssl_certificate()
                    ssl.match_hostname(client_cert, agent_id)

                    # Execute specified script if all is well
                    global INIT_SCRIPT
                    if INIT_SCRIPT is not None and INIT_SCRIPT != "":

                        def initthread():
                            import subprocess

                            logger.debug("Executing specified script: %s" % INIT_SCRIPT)
                            env = os.environ.copy()
                            env["AGENT_UUID"] = agent_id
                            proc = subprocess.Popen(
                                ["/bin/sh", INIT_SCRIPT],
                                env=env,
                                shell=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                            )
                            proc.wait()
                            while True:
                                line = proc.stdout.readline()
                                if line == "":
                                    break
                                logger.debug("init-output: %s" % line.strip())

                        thread = threading.Thread(target=initthread)
                        thread.start()

                    keylime.web_util.echo_json_response(self, 200, "Success", json_body)
                    logger.info("POST returning 200 response for Agent Monitor connection as " + agent_id)
            else:
                keylime.web_util.echo_json_response(self, 400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported")
        except Exception as err:
            keylime.web_util.echo_json_response(self, 400, "Exception error: %s" % err)
            logger.exception("POST returning 400 response.")

    def put(self):
        """This method handles the PUT requests to add agents to the Agent Monitor.

        Currently, only agents resources are available for PUTing, i.e. /agents. All other PUT uri's will return errors.
        agents requests require a json block sent in the body
        """
        keylime.web_util.echo_json_response(self, 405, "PUT not supported")


def init_mtls(config):
    logger.info("Setting up mTLS...")

    tls_dir = config["ca_dir"]
    if tls_dir[0] != "/":
        tls_dir = os.path.abspath("%s/%s" % (common.WORK_DIR, tls_dir))

    # We need to securely pull in the ca password
    my_key_pw = getpass.getpass("Please enter the password to decrypt your keystore: ")
    ca_util.setpassword(my_key_pw)

    # Create HIL Server Connect certs (if not already present)
    if not os.path.exists("%s/%s-cert.crt" % (tls_dir, config["ip"])):
        logger.info("Generating new Agent Monitor TLS Certs in %s for connecting" % tls_dir)
        ca_util.cmd_mkcert(tls_dir, config["ip"])

    ca_path = "%s/cacert.crt" % (tls_dir)
    my_cert = "%s/%s-cert.crt" % (tls_dir, config["ip"])
    my_priv_key = "%s/%s-private.pem" % (tls_dir, config["ip"])

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_verify_locations(cafile=ca_path)
    context.load_cert_chain(certfile=my_cert, keyfile=my_priv_key, password=my_key_pw)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def start_tornado(tornado_server, port):
    tornado_server.listen(port)
    print("Starting Torando on port " + str(port))
    tornado.ioloop.IOLoop.instance().start()
    print("Tornado finished")


def main(argv=sys.argv):
    """Main method of Agent Monitor.  This method is encapsulated in a function for packaging to allow it to be
    called as a function by an external program."""
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument(
        "-p",
        "--port",
        action="store",
        default="6892",
        help="Port for the Agent Monitor to listen on (defaults to 6892)",
    )
    parser.add_argument(
        "-i",
        "--ip",
        action="store",
        default="localhost",
        help="IP address for the Agent Monitor (defaults to localhost)",
    )
    parser.add_argument(
        "-s", "--script", action="store", default=None, help="Specify the script to execute when the agent phones home"
    )
    parser.add_argument(
        "-c",
        "--cert",
        action="store",
        dest="ca_dir",
        default=None,
        help='Tenant-generated certificate. Pass in the CA directory or use "default" to use the standard dir',
    )
    args = parser.parse_args(argv[1:])

    # Find out where the certs are stored by tenant
    if args.ca_dir is None or args.ca_dir == "default":
        args.ca_dir = common.CA_WORK_DIR

    # Make initscript available to tornado callback
    global INIT_SCRIPT
    INIT_SCRIPT = args.script

    logger.info("Starting Agent Monitor (tornado) on port " + args.port + ", use <Ctrl-C> to stop")

    app = tornado.web.Application(
        [
            (r"/", MainHandler),
            (r"/(?:v[0-9]/)?agents/.*", AgentsHandler),
        ]
    )

    context = init_mtls(vars(args))
    server = tornado.httpserver.HTTPServer(app, ssl_options=context)
    server.bind(int(args.port), address="0.0.0.0")
    server.start(0)

    try:
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt:
        tornado.ioloop.IOLoop.instance().stop()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
