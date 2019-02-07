package body TLS_Handshake is

   function Convert_To_Extension_Type (Buffer : Types.Bytes; Offset : Natural) return Extension_Type is
      Raw : Extension_Type_Base := Convert_To_Extension_Type_Base (Buffer, Offset);
   begin
      return (case Raw is when 0 => (True, EXTENSION_SERVER_NAME), when 1 => (True, EXTENSION_MAX_FRAGMENT_LENGTH), when 5 => (True, EXTENSION_STATUS_REQUEST), when 10 => (True, EXTENSION_SUPPORTED_GROUPS), when 13 => (True, EXTENSION_SIGNATURE_ALGORITHMS), when 14 => (True, EXTENSION_USE_SRTP), when 15 => (True, EXTENSION_HEARTBEAT), when 16 => (True, EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), when 18 => (True, EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP), when 19 => (True, EXTENSION_CLIENT_CERTIFICATE_TYPE), when 20 => (True, EXTENSION_SERVER_CERTIFICATE_TYPE), when 21 => (True, EXTENSION_PADDING), when 41 => (True, EXTENSION_PRE_SHARED_KEY), when 42 => (True, EXTENSION_EARLY_DATA), when 43 => (True, EXTENSION_SUPPORTED_VERSIONS), when 44 => (True, EXTENSION_COOKIE), when 45 => (True, EXTENSION_PSK_KEY_EXCHANGE_MODES), when 47 => (True, EXTENSION_CERTIFICATE_AUTHORITIES), when 48 => (True, EXTENSION_OID_FILTERS), when 49 => (True, EXTENSION_POST_HANDSHAKE_AUTH), when 50 => (True, EXTENSION_SIGNATURE_ALGORITHMS_CERT), when 51 => (True, EXTENSION_KEY_SHARE), when others => (False, Raw));
   end Convert_To_Extension_Type;

end TLS_Handshake;
