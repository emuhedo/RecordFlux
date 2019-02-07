with Types;
use type Types.Index_Type, Types.Length_Type;

package TLS_Alert
  with SPARK_Mode
is

   type Alert_Level_Base is mod (2**8);
   function Convert_To_Alert_Level_Base is new Types.Convert_To_Mod (Alert_Level_Base);

   type Alert_Level is (WARNING, FATAL) with Size => 8;
   for Alert_Level use (WARNING => 1, FATAL => 2);

   type Alert_Description_Type_Base is mod (2**8);
   function Convert_To_Alert_Description_Type_Base is new Types.Convert_To_Mod (Alert_Description_Type_Base);

   type Alert_Description_Type is (CLOSE_NOTIFY, UNEXPECTED_MESSAGE, BAD_RECORD_MAC, RECORD_OVERFLOW, HANDSHAKE_FAILURE, BAD_CERTIFICATE, UNSUPPORTED_CERTIFICATE, CERTIFICATE_REVOKED, CERTIFICATE_EXPIRED, CERTIFICATE_UNKNOWN, ILLEGAL_PARAMETER, UNKNOWN_CA, ACCESS_DENIED, DECODE_ERROR, DECRYPT_ERROR, PROTOCOL_VERSION, INSUFFICIENT_SECURITY, INTERNAL_ERROR, INAPPROPRIATE_FALLBACK, USER_CANCELED, MISSING_EXTENSION, UNSUPPORTED_EXTENSION, UNRECOGNIZED_NAME, BAD_CERTIFICATE_STATUS_RESPONSE, UNKNOWN_PSK_IDENTITY, CERTIFICATE_REQUIRED, NO_APPLICATION_PROTOCOL) with Size => 8;
   for Alert_Description_Type use (CLOSE_NOTIFY => 0, UNEXPECTED_MESSAGE => 10, BAD_RECORD_MAC => 20, RECORD_OVERFLOW => 22, HANDSHAKE_FAILURE => 40, BAD_CERTIFICATE => 42, UNSUPPORTED_CERTIFICATE => 43, CERTIFICATE_REVOKED => 44, CERTIFICATE_EXPIRED => 45, CERTIFICATE_UNKNOWN => 46, ILLEGAL_PARAMETER => 47, UNKNOWN_CA => 48, ACCESS_DENIED => 49, DECODE_ERROR => 50, DECRYPT_ERROR => 51, PROTOCOL_VERSION => 70, INSUFFICIENT_SECURITY => 71, INTERNAL_ERROR => 80, INAPPROPRIATE_FALLBACK => 86, USER_CANCELED => 90, MISSING_EXTENSION => 109, UNSUPPORTED_EXTENSION => 110, UNRECOGNIZED_NAME => 112, BAD_CERTIFICATE_STATUS_RESPONSE => 113, UNKNOWN_PSK_IDENTITY => 115, CERTIFICATE_REQUIRED => 116, NO_APPLICATION_PROTOCOL => 120);

   pragma Warnings (Off, "precondition is statically false");

   function Unreachable_Alert_Level return Alert_Level is
      (Alert_Level'First)
     with
       Pre => False;

   function Unreachable_Alert_Description_Type return Alert_Description_Type is
      (Alert_Description_Type'First)
     with
       Pre => False;

   function Unreachable_Types_Length_Type return Types.Length_Type is
      (Types.Length_Type'First)
     with
       Pre => False;

   pragma Warnings (On, "precondition is statically false");

   function Valid_Alert_Level (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Alert_Level_Base (Buffer, Offset) is when 1 | 2 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Alert_Level_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Alert_Level (Buffer : Types.Bytes; Offset : Natural) return Alert_Level is
      (case Convert_To_Alert_Level_Base (Buffer, Offset) is when 1 => WARNING, when 2 => FATAL, when others => Unreachable_Alert_Level)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Alert_Level_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Alert_Level (Buffer, Offset));

   function Valid_Alert_Description_Type (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Alert_Description_Type_Base (Buffer, Offset) is when 0 | 10 | 20 | 22 | 40 | 42 | 43 | 44 | 45 | 46 | 47 | 48 | 49 | 50 | 51 | 70 | 71 | 80 | 86 | 90 | 109 | 110 | 112 | 113 | 115 | 116 | 120 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Alert_Description_Type_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Alert_Description_Type (Buffer : Types.Bytes; Offset : Natural) return Alert_Description_Type is
      (case Convert_To_Alert_Description_Type_Base (Buffer, Offset) is when 0 => CLOSE_NOTIFY, when 10 => UNEXPECTED_MESSAGE, when 20 => BAD_RECORD_MAC, when 22 => RECORD_OVERFLOW, when 40 => HANDSHAKE_FAILURE, when 42 => BAD_CERTIFICATE, when 43 => UNSUPPORTED_CERTIFICATE, when 44 => CERTIFICATE_REVOKED, when 45 => CERTIFICATE_EXPIRED, when 46 => CERTIFICATE_UNKNOWN, when 47 => ILLEGAL_PARAMETER, when 48 => UNKNOWN_CA, when 49 => ACCESS_DENIED, when 50 => DECODE_ERROR, when 51 => DECRYPT_ERROR, when 70 => PROTOCOL_VERSION, when 71 => INSUFFICIENT_SECURITY, when 80 => INTERNAL_ERROR, when 86 => INAPPROPRIATE_FALLBACK, when 90 => USER_CANCELED, when 109 => MISSING_EXTENSION, when 110 => UNSUPPORTED_EXTENSION, when 112 => UNRECOGNIZED_NAME, when 113 => BAD_CERTIFICATE_STATUS_RESPONSE, when 115 => UNKNOWN_PSK_IDENTITY, when 116 => CERTIFICATE_REQUIRED, when 120 => NO_APPLICATION_PROTOCOL, when others => Unreachable_Alert_Description_Type)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Alert_Description_Type_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Alert_Description_Type (Buffer, Offset));

end TLS_Alert;
