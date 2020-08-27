from abc import ABC, abstractmethod

from duoauthproxy.lib import duo_async, log


class ApiErrorHandling(ABC):
    @abstractmethod
    def log_request(self, request, msg):
        pass

    @abstractmethod
    def create_accept_packet(self, request, msg, primary_res):
        pass

    @abstractmethod
    def create_reject_packet(self, request, msg, radius_attrs):
        pass

    def response_for_api_error(self, request, primary_res, e, radius_reject_attrs=None):
        """Build and return a response packet for the given request, primary response,
        and api error.  Assumes the primary response is success.  Include the
        passed-in radius attributes when building a rejection packet.

        Returns a response ready to send to the client.
        """
        if duo_async.should_server_fail_open(self.failmode, e.fail_open):
            msg = duo_async.get_fail_open_msg()
            self.log_request(request, msg)

            log.auth_standard(
                msg=msg,
                username=request.username,
                auth_stage=log.AUTH_SECONDARY,
                status=log.AUTH_ALLOW,
                client_ip=request.client_ip,
                server_section=self.server_section_name,
                server_section_ikey=self.server_section_ikey,
            )

            return self.create_accept_packet(request, msg, primary_res.radius_attrs,)

        msg = duo_async.FAILMODE_SECURE_MSG
        self.log_request(request, msg)

        log.auth_standard(
            msg=msg,
            username=request.username,
            auth_stage=log.AUTH_SECONDARY,
            status=log.AUTH_REJECT,
            client_ip=request.client_ip,
            server_section=self.server_section_name,
            server_section_ikey=self.server_section_ikey,
        )

        if radius_reject_attrs is None:
            radius_reject_attrs = {}

        return self.create_reject_packet(request, msg, radius_attrs=radius_reject_attrs)
