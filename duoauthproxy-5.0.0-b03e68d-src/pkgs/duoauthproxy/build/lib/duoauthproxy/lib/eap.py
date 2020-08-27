# pylint: disable=E0202,E0203,W0612
import struct
from typing import TYPE_CHECKING, Iterator, Optional, Union

from OpenSSL import SSL
from twisted.internet import defer

from duoauthproxy.lib import log
from duoauthproxy.lib.radius.server import _ProxyRequest
from duoauthproxy.modules import ssl_server

if TYPE_CHECKING:
    from duoauthproxy.modules.radius_server_eap import DuoEAPRadiusServer

EAP_SESSION_START = 0
EAP_SESSION_REQUEST_PEAP = 1
EAP_SESSION_PEAP_START = 2
EAP_SESSION_PEAP_REQUEST = 3
EAP_SESSION_PEAP = 4
EAP_SESSION_PEAP_MORE = 5
EAP_SESSION_REQUEST_GTC = 6
EAP_SESSION_PEAP_GTC = 7
EAP_SESSION_ACCEPT = 8
EAP_SESSION_PEAP_ID = 9
EAP_SESSION_PEAP_ACCEPT = 10
EAP_SESSION_SUCCESS = 11
EAP_SESSION_DENY = 12
EAP_SESSION_PEAP_DENY = 13
EAP_SESSION_FAILURE = 14

EAP_FAILURE = 0
EAP_SUCCESS = 1
EAP_PASSCODE = 2

EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4

EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK = 3
EAP_TYPE_GTC = 6
EAP_TYPE_PEAP = 25
EAP_TYPE_NONE = 0
EAP_TYPE_TLV = 33

MS_RESULT_HEADER = b"\x80\x03"


class EAPPacketException(Exception):
    pass


class EAPPacket(object):
    def __init__(
        self,
        code: int,
        ID: int,
        eap_type: int,
        data: Union[bytes, bool, int],
        length: int = 0,
        start: bool = False,
        more: bool = False,
    ):
        """Class representation of an EAP packet.
        Args:
            code (int): one of 1 through 4 to represent the type of EAP packet
                (Request, Response, Success, Failure)
            ID (int): packet identifier
            eap_type (int): type of EAP Request or Response. Empty for Success and Failure
                packets.
            data (bytes, bool, or int): actual packet data.  bytes most of the time, bool for TLV type, int for NAK type
            length (int): length of the entire packet (code, ID, length, and data fields)
            start (bool): ???
            more (bool): ???
        """

        self.ID = ID
        self.code = code
        self.type = eap_type

        if eap_type == EAP_TYPE_IDENTITY:
            self.add_id(bytes(data))
        elif eap_type == EAP_TYPE_NOTIFICATION:
            self.add_not(bytes(data))
        elif eap_type == EAP_TYPE_NAK:
            self.add_nak(int(data))
        elif eap_type == EAP_TYPE_GTC:
            self.add_gtc(bytes(data))
        elif eap_type == EAP_TYPE_PEAP:
            self.add_peap(bytes(data), length, start, more)
        elif eap_type == EAP_TYPE_NONE:
            self.data = bytes(data)
        elif eap_type == EAP_TYPE_TLV:
            # MS accept tlv
            self.add_tlv(bool(data))
        else:
            raise EAPPacketException("Unsupported eap type %s" % eap_type)

    def add_id(self, data: bytes):
        self.data = data

    def add_not(self, data: bytes):
        self.data = data

    def add_nak(self, data: int):
        try:
            self.data = chr(data).encode()
        except (ValueError, TypeError):
            raise EAPPacketException("Invalid Nak type %s" % data)

    def add_gtc(self, data: bytes):
        self.data = data

    def add_peap(self, data: bytes, length=0, start=False, more=False):
        """
        start should be true if first fragment
        more should be true if not last fragment
        length must be the EAP-TLS Length
        """

        flags = 0
        if start:
            flags = flags | 32  # TLS-start
            if length:
                flags = flags | 128  # Length Included

        if more:
            flags = flags | 64  # More Fragments

        self.data = chr(flags).encode()

        if length:
            self.data += struct.pack(">I", length)
        self.data += data

    def add_tlv(self, result: bool):
        # MS Result TLV packet
        # M bit flag = 1, TLV_Type = 3, Length=2
        result_code = int(1 if result is True else 2)
        self.data = struct.pack("BBBBBB", 128, 3, 0, 2, 0, result_code)

    def render(self) -> bytes:
        """Creates a bytestring representation of this EAP packet to be sent.

        EAP packet format:
        EAP code [1-4] | Packet identifier | Packet length | Packet type (if any) | Packet data

        Returns:
            bytes: bytestring repr of the packet
        Raises:
            EAPPacketException
        """
        try:
            msg = chr(self.code).encode()
            msg += chr(self.ID).encode()
            if self.type:
                msg += struct.pack(">H", 5 + len(self.data))
                msg += chr(self.type).encode()
            else:
                msg += struct.pack(">H", 4)
            msg += self.data
            return msg
        except ValueError:
            raise EAPPacketException("Invalid EAP code, type or ID")


class EAPSession(object):
    def __init__(
        self,
        pkey: str = None,
        certs: str = None,
        inner: bool = False,
        gtc_message: bytes = b"Enter your password",
        parent: "Optional[EAPSession]" = None,
        cipher_list: str = "",
        minimum_tls_version: Optional[str] = None,
    ) -> None:
        """Partially abstract class representing a PEAP session between the
        server and a client.

        Args:
            pkey (str): Path to private key file. Required.
            certs (str): Path to X509 certificate file. Required.
            inner bool): ???
            gtc_message (bytes): Message to display to the user during 1FA challenge
            parent (???): ???
            cipher_list (str): Possibly empty list of semicolon-delimited
                OpenSSL cipher suites
            minimum_tls_version (str): Minimum TLS version for the server
        """
        self.mk: bytes
        self.cr: bytes
        self.sr: bytes
        self.innerEAP: EAPSession
        self.current_request: _ProxyRequest
        self.server: "DuoEAPRadiusServer"
        self.tls_msg: bytes

        self.inner = inner
        self.gtc_message = gtc_message
        self.state = 0
        self.id = 0
        self.pkey = pkey
        self.certs = certs
        self.password = None
        self.prompt = ""
        self.enrolling = False
        self.next_state = ""
        self.handshake = False
        self.parent = parent
        self.cipher_list = cipher_list
        self.minimum_tls_version = minimum_tls_version

    def gtc_received(self, session, passcode, prompt):
        """ Called when the response to a gtc prompt is received """
        raise NotImplementedError()

    def errback(self, session, reason):
        """ Called when the eap session fails for some reason. """
        raise NotImplementedError()

    def success(self, session):
        """ Called when authentication is successful """
        raise NotImplementedError()

    @staticmethod
    def inner_errback(session, reason):
        return Exception(reason)

    @staticmethod
    def inner_success(session):
        return True

    def start_tls(self, pkey_file, certs_file, cipher_list, minimum_tls_version):
        """Starts a PEAP session between this server and its client.
        Creates the SSL tunnel context to begin PEAP and starts its underlying
        EAP method's session.

        Args:
            pkey_file (str): path to private key file
            certs_file (str): path to X509 certificate file
            cipher_list (str): possibly empty list of semicolon-delimited
                OpenSSL cipher suites
            minimum_tls_version (str): the minimum TLS version for the server to accept
        """
        ssl_context_factory = ssl_server.ChainingOpenSSLContextFactory(
            privatekey_filename=pkey_file,
            certificate_filename=certs_file,
            cipher_list=cipher_list,
            minimum_tls_version=minimum_tls_version,
        )

        ssl_context = ssl_context_factory.getContext()
        self.ssl_con = SSL.Connection(ssl_context, None)
        self.handshake = False

        # Create inner EAP session and let it use the implemented callbacks
        self.innerEAP = EAPSession(
            inner=True, gtc_message=self.gtc_message, parent=self
        )
        self.innerEAP.gtc_received = self.gtc_received
        self.innerEAP.errback = self.inner_errback
        self.innerEAP.success = self.inner_success

    def get_outgoing(self) -> Optional[bytes]:
        # Check to see if there are outgoing messages from the SSL connection
        try:
            return self.ssl_con.bio_read(4096)
        except SSL.WantReadError:
            # No outgoing messages ready
            return None

    @defer.inlineCallbacks
    def add_incoming(self, msg: bytes):
        # Add a message to the EAP-TLS connection
        self.ssl_con.bio_write(msg)
        if not self.handshake:
            try:
                self.ssl_con.set_accept_state()
                self.ssl_con.do_handshake()
            except SSL.WantReadError:
                self.handshake = True
        try:
            # If there is a decrypted message ready, push it to inner eap
            decrypted_msg = self.ssl_con.recv(9999)  # bytes

            # Inner eap lacks code, id, len
            # add them on so the packet is parsed the same
            header = (
                chr(2).encode() + msg[1:2] + struct.pack(">H", len(decrypted_msg) + 4)
            )  # bytes

            if (
                decrypted_msg[0] == 2
            ):  
                # For some reason the MS-Auth-TLV has a header already
                header = b""
            elif decrypted_msg[0] == 6:
                # GTC response
                gtc = yield self.gtc_received(self, decrypted_msg[1:], self.gtc_message)
                defer.returnValue(gtc)

            add_response = yield self.innerEAP.add_message(header + decrypted_msg)
            if add_response:
                error = yield self.errback(self, add_response.message)
                defer.returnValue(error)

        except SSL.WantReadError:
            # No decrypted message ready yet
            pass
        except SSL.Error as e:
            # Possibly retransmission or some other unknown error
            ssl_error = "SSL Error: {0}".format(e)
            log.auth_standard(
                msg=ssl_error,
                username=self.current_request.username,
                auth_stage=log.AUTH_UNKNOWN,
                status=log.AUTH_ERROR,
                client_ip=self.current_request.client_ip,
                server_section=self.server.server_section_name,
                server_section_ikey=self.server.server_section_ikey,
            )
            error = yield self.errback(self, ssl_error)
            defer.returnValue(error)

        defer.returnValue(False)

    @defer.inlineCallbacks
    def next_message(self) -> Iterator[bytes]:
        """Get the next outgoing message from the EAP session.

        Returns:
            str: contains message, if any
            pyrad.Packet: if authentication was successful. Result of calling this
                class' self.success() method.
            errback: if authentication was not successful
        """

        if self.state == EAP_SESSION_START:
            # Request Identity
            packet = EAPPacket(
                EAP_CODE_REQUEST, self.id, EAP_TYPE_IDENTITY, chr(0).encode()
            )

        elif self.state == EAP_SESSION_REQUEST_PEAP:
            # Send a Nak PEAP request
            packet = EAPPacket(EAP_CODE_REQUEST, self.id, EAP_TYPE_NAK, EAP_TYPE_PEAP)

        elif self.state == EAP_SESSION_PEAP_REQUEST:
            # Start a TLS session and send TLS-start packet
            self.start_tls(
                self.pkey, self.certs, self.cipher_list, self.minimum_tls_version
            )
            packet = EAPPacket(
                EAP_CODE_REQUEST, self.id, EAP_TYPE_PEAP, b"", start=True
            )

        elif self.state == EAP_SESSION_PEAP:
            # Currently in a PEAP session

            # Check to see if the TLS connection has outgoing messages
            outgoing_msg = self.get_outgoing()
            if outgoing_msg:
                packet = EAPPacket(
                    EAP_CODE_REQUEST, self.id, EAP_TYPE_PEAP, outgoing_msg
                )

            else:
                # The tls connection has nothing to send
                # Get a message from inner EAP and feed it to tls
                # Connection then retry to find something to send
                inner_msg = yield self.innerEAP.next_message()

                # Upon error or success, next_message will yield
                #  an exception or a boolean respectively
                if isinstance(inner_msg, bytes):
                    self.ssl_con.send(inner_msg)
                    msg = yield self.next_message()
                    defer.returnValue(msg)
                elif isinstance(inner_msg, Exception):
                    log.auth_standard(
                        msg=repr(inner_msg),
                        username=self.current_request.username,
                        auth_stage=log.AUTH_UNKNOWN,
                        status=log.AUTH_ERROR,
                        client_ip=self.current_request.client_ip,
                        server_section=self.server.server_section_name,
                        server_section_ikey=self.server.server_section_ikey,
                    )
                    error = yield self.errback(self, repr(inner_msg))
                    defer.returnValue(error)
                elif inner_msg is True:
                    success = yield self.success(self)
                    defer.returnValue(success)
                else:
                    peap_error_message = "Error in PEAP session"
                    log.auth_standard(
                        msg=peap_error_message,
                        username=self.current_request.username,
                        auth_stage=log.AUTH_UNKNOWN,
                        status=log.AUTH_ERROR,
                        client_ip=self.current_request.client_ip,
                        server_section=self.server.server_section_name,
                        server_section_ikey=self.server.server_section_ikey,
                    )
                    error = self.errback(self, peap_error_message)
                    defer.returnValue(error)

        elif self.state == EAP_SESSION_REQUEST_GTC:
            # Send a password (GTC) prompt
            packet = EAPPacket(
                EAP_CODE_REQUEST, self.id, EAP_TYPE_GTC, self.gtc_message
            )

        elif self.state == EAP_SESSION_PEAP_GTC:
            # Have inner EAP send GTC prompt
            self.innerEAP.state = EAP_SESSION_REQUEST_GTC
            self.state = EAP_SESSION_PEAP
            msg = yield self.next_message()
            defer.returnValue(msg)

        elif self.state == EAP_SESSION_PEAP_ID:
            # Have inner EAP request ID
            self.innerEAP.state = EAP_SESSION_START
            self.state = EAP_SESSION_PEAP
            msg = yield self.next_message()
            defer.returnValue(msg)

        elif self.state == EAP_SESSION_PEAP_ACCEPT:
            # Save the TLS key/randoms for generating MPPE keys
            self.mk = self.ssl_con.master_key()
            self.cr = self.ssl_con.client_random()
            self.sr = self.ssl_con.server_random()

            # Have inner EAP send accept message
            self.innerEAP.state = EAP_SESSION_ACCEPT
            self.state = EAP_SESSION_PEAP
            msg = yield self.next_message()
            defer.returnValue(msg)

        elif self.state == EAP_SESSION_PEAP_DENY:
            # Have inner EAP send reject message
            self.innerEAP.state = EAP_SESSION_DENY
            self.state = EAP_SESSION_PEAP
            msg = yield self.next_message()
            defer.returnValue(msg)

        elif self.state == EAP_SESSION_ACCEPT:
            # Send accept packet
            packet = EAPPacket(EAP_CODE_REQUEST, self.id, EAP_TYPE_TLV, True)

        elif self.state == EAP_SESSION_DENY:
            error = yield self.errback(self, "Authentication denied.")
            defer.returnValue(error)

        elif self.state == EAP_SESSION_FAILURE:
            error = yield self.errback(self, "EAP session failed.")
            defer.returnValue(error)

        elif self.state == EAP_SESSION_SUCCESS:
            success = yield self.success(self)
            defer.returnValue(success)

        if self.inner:
            defer.returnValue(
                packet.render()[4:]
            )  # tunneled EAP skips code, id, length
        defer.returnValue(packet.render())

    @defer.inlineCallbacks
    def add_message(self, msg: bytes):
        """Add a message to the EAP session.
        Returns False on success, returns errback on error, or gtc_received
        on receiving a token card response.
        """
        code, identifier, length, eap_type = struct.unpack(">BBHB", msg[:5])
        if not self.inner and self.id != 0 and identifier != self.id:
            # Silently discard response if ID does not match
            log.msg(
                "Response ID %s does not match request ID %s" % (identifier, self.id)
            )
            defer.returnValue(False)
        if len(msg) != length:
            message = "Malformed EAP packet: length ({0}) does not match actual length ({1})".format(
                length, len(msg)
            )
            log.auth_standard(
                msg=message,
                username=self.current_request.username,
                auth_stage=log.AUTH_UNKNOWN,
                status=log.AUTH_ERROR,
                client_ip=self.current_request.client_ip,
                server_section=self.server.server_section_name,
                server_section_ikey=self.server.server_section_ikey,
            )
            error = yield self.errback(self, message)
            defer.returnValue(error)

        if code == EAP_CODE_REQUEST:
            # EAP request, we are talking to RADIUS, this should not happen
            message = "EAP request received."
            log.auth_standard(
                msg=message,
                username=self.current_request.username,
                auth_stage=log.AUTH_UNKNOWN,
                status=log.AUTH_ERROR,
                client_ip=self.current_request.client_ip,
                server_section=self.server.server_section_name,
                server_section_ikey=self.server.server_section_ikey,
            )
            error = yield self.errback(self, message)
            defer.returnValue(error)
        elif code == EAP_CODE_RESPONSE:
            # EAP response, we are talking to NetMotion
            self.id += 1
            if eap_type == EAP_TYPE_IDENTITY:  # Identity
                self.state = EAP_SESSION_REQUEST_GTC
            elif eap_type == EAP_TYPE_NAK:  # Legacy Nak
                # Data element (element 5) will indicate the desired type
                desired_type = msg[5]
                if desired_type == EAP_TYPE_PEAP:  # PEAP request
                    self.state = EAP_SESSION_PEAP_REQUEST
                else:
                    message = "Unknown Nak request %s." % desired_type
                    log.auth_standard(
                        msg=message,
                        username=self.current_request.username,
                        auth_stage=log.AUTH_UNKNOWN,
                        status=log.AUTH_ERROR,
                        client_ip=self.current_request.client_ip,
                        server_section=self.server.server_section_name,
                        server_section_ikey=self.server.server_section_ikey,
                    )
                    error = yield self.errback(self, message)
                    defer.returnValue(error)
            elif eap_type == EAP_TYPE_TLV:
                if msg[5:7] == MS_RESULT_HEADER and len(msg) == 11:  # MS-Result-TLV
                    if msg[-1] == 1 and self.state == EAP_SESSION_ACCEPT:  # Success
                        self.state = EAP_SESSION_SUCCESS
                    else:  # Failure
                        self.state = EAP_SESSION_FAILURE
                else:
                    # No support for cryptobinding or SoH TLV
                    # At least exit with some relevant info
                    message = "Unsupported TLV: {0!r}.".format(msg)
                    log.auth_standard(
                        msg=message,
                        username=self.current_request.username,
                        auth_stage=log.AUTH_UNKNOWN,
                        status=log.AUTH_ERROR,
                        client_ip=self.current_request.client_ip,
                        server_section=self.server.server_section_name,
                        server_section_ikey=self.server.server_section_ikey,
                    )
                    error = yield self.errback(self, message)
                    defer.returnValue(error)

            elif eap_type == EAP_TYPE_PEAP:  # PEAP
                tls_flags = msg[5]
                if tls_flags & 0x80:  # Length included
                    self.tls_len = struct.unpack(">I", msg[6:10])
                    tls_msg: bytes = msg[10:]
                else:
                    tls_msg = msg[6:]

                if self.state == EAP_SESSION_PEAP_MORE:
                    self.tls_msg += tls_msg
                else:
                    self.tls_msg = tls_msg

                if tls_flags & 0x40:  # More fragments
                    self.state = EAP_SESSION_PEAP_MORE
                else:
                    self.state = EAP_SESSION_PEAP
                    if self.tls_msg:
                        if hasattr(self, "ssl_con"):
                            add_response = yield self.add_incoming(tls_msg)
                            if add_response:
                                # Errback or gtc callback occured, pass it through
                                defer.returnValue(add_response)
                        else:
                            # We reset the EAP session but the peer is trying to continue
                            self.state = EAP_SESSION_PEAP_REQUEST
                    else:
                        # Empty PEAP message, probably handshake over
                        self.state = EAP_SESSION_PEAP_ID
        defer.returnValue(False)
