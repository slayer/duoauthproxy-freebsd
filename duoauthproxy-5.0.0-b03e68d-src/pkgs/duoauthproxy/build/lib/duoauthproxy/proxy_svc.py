#
# Copyright (c) 2011 Duo Security
# All Rights Reserved
#

from twisted.internet import iocpreactor  # isort:skip

iocpreactor.install()  # isort:skip XXX this needs to go early in the import list

import os
import subprocess
import traceback

import servicemanager
import win32event
import win32evtlogutil
import win32serviceutil
from twisted.application import app
from twisted.internet import reactor

import duoauthproxy.proxy
from duoauthproxy.lib import util


class MyService(win32serviceutil.ServiceFramework):
    _svc_name_ = "DuoAuthProxy"
    _svc_display_name_ = "Duo Security Authentication Proxy Service"
    _svc_deps_ = ["EventLog"]

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.duo_root = util.get_home_dir()

    def SvcStop(self):
        reactor.callFromThread(reactor.stop)
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

    def SvcDoRun(self):
        win32evtlogutil.AddSourceToRegistry(self._svc_name_, servicemanager.__file__)

        # Write a 'started' event to the event log...
        win32evtlogutil.ReportEvent(
            self._svc_name_,
            servicemanager.PYS_SERVICE_STARTED,
            0,  # category
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            (self._svc_name_, ""),
        )

        try:
            return_code = self.run_connectivity_tool()
            if return_code != 0:
                # raise Exception("Authentication Proxy Configuration has an error.")

                # We're choosing not to prevent auth proxy startup if there are
                # config errors for now, but once the configuration validation
                # proves to be stable we can go back to preventing startup.
                message = (
                    "Your configuration is not valid. Check the output "
                    "at {conn_tool_logs} for errors.".format(
                        conn_tool_logs=self.conn_tool_logs
                    )
                )
                self.log_error_during_startup(message)

            application = duoauthproxy.proxy.create_application()
            app.startApplication(application, 0)
            reactor.run(installSignalHandlers=0)
        except Exception:
            # service did not shut down cleanly
            message = traceback.format_exc()
            win32evtlogutil.ReportEvent(
                self._svc_name_,
                servicemanager.PYS_SERVICE_STOPPED,
                0,  # category
                servicemanager.EVENTLOG_ERROR_TYPE,
                (
                    self._svc_name_,
                    " due to a failure:\n\n%s\n"
                    "We could not start your Authentication Proxy due to an error. Likely this is a configuration error. To view the error output check the logs located at %s \n"
                    "After fixing the errors you can run a test of your configuration using our validator located at %s"
                    % (message, self.conn_tool_logs, self.conn_tool_path),
                ),
            )
        else:
            # service shut down cleanly
            win32evtlogutil.ReportEvent(
                self._svc_name_,
                servicemanager.PYS_SERVICE_STOPPED,
                0,  # category
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                (self._svc_name_, ""),
            )

        win32event.SetEvent(self.hWaitStop)

    def run_connectivity_tool(self):
        conn_tool = self.conn_tool_path
        try:
            return subprocess.call(
                [conn_tool, "--no-explicit-connectivity-check", "--startup"]
            )
        except OSError as e:
            msg = " but failed to run the connectivity tool due to a failure:\n\n{0}\n".format(
                str(e)
            )
            self.log_error_during_startup(msg)
            return 0

    def log_error_during_startup(self, msg):
        """ Log an error that occurs during startup process
        Args:
            msg (str): Fill in the blank! "The DuoAuthProxy service is starting ____
        """
        win32evtlogutil.ReportEvent(
            self._svc_name_,
            servicemanager.PYS_SERVICE_STARTING,
            0,  # category
            servicemanager.EVENTLOG_ERROR_TYPE,
            (self._svc_name_, msg),
        )

    @property
    def conn_tool_path(self):
        return os.path.join(self.duo_root, "bin", "authproxy_connectivity_tool")

    @property
    def conn_tool_logs(self):
        return os.path.join(self.duo_root, "log", "connectivity_tool.log")


if __name__ == "__main__":
    # Note that this code will not be run in the 'frozen' exe-file!!!
    win32serviceutil.HandleCommandLine(MyService)
