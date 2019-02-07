with Types;
use type Types.Index_Type, Types.Length_Type;

package TLS_Record
  with SPARK_Mode
is

   type Content_Type_Base is mod (2**8);
   function Convert_To_Content_Type_Base is new Types.Convert_To_Mod (Content_Type_Base);

   type Content_Type is (INVALID, CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA, HEARTBEAT) with Size => 8;
   for Content_Type use (INVALID => 0, CHANGE_CIPHER_SPEC => 20, ALERT => 21, HANDSHAKE => 22, APPLICATION_DATA => 23, HEARTBEAT => 24);

   type Protocol_Version_Type_Base is mod (2**16);
   function Convert_To_Protocol_Version_Type_Base is new Types.Convert_To_Mod (Protocol_Version_Type_Base);

   type Protocol_Version_Type is (TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3) with Size => 16;
   for Protocol_Version_Type use (TLS_1_0 => 769, TLS_1_1 => 770, TLS_1_2 => 771, TLS_1_3 => 772);

   type Length_Type is mod (2**16);
   function Convert_To_Length_Type is new Types.Convert_To_Mod (Length_Type);

   pragma Warnings (Off, "precondition is statically false");

   function Unreachable_Content_Type return Content_Type is
      (Content_Type'First)
     with
       Pre => False;

   function Unreachable_Protocol_Version_Type return Protocol_Version_Type is
      (Protocol_Version_Type'First)
     with
       Pre => False;

   function Unreachable_Length_Type return Length_Type is
      (Length_Type'First)
     with
       Pre => False;

   function Unreachable_Types_Index_Type return Types.Index_Type is
      (Types.Index_Type'First)
     with
       Pre => False;

   function Unreachable_Types_Length_Type return Types.Length_Type is
      (Types.Length_Type'First)
     with
       Pre => False;

   pragma Warnings (On, "precondition is statically false");

   function Valid_Content_Type (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Content_Type_Base (Buffer, Offset) is when 0 | 20 | 21 | 22 | 23 | 24 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Content_Type_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Content_Type (Buffer : Types.Bytes; Offset : Natural) return Content_Type is
      (case Convert_To_Content_Type_Base (Buffer, Offset) is when 0 => INVALID, when 20 => CHANGE_CIPHER_SPEC, when 21 => ALERT, when 22 => HANDSHAKE, when 23 => APPLICATION_DATA, when 24 => HEARTBEAT, when others => Unreachable_Content_Type)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Content_Type_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Content_Type (Buffer, Offset));

   function Valid_Protocol_Version_Type (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Protocol_Version_Type_Base (Buffer, Offset) is when 769 | 770 | 771 | 772 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Protocol_Version_Type_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Protocol_Version_Type (Buffer : Types.Bytes; Offset : Natural) return Protocol_Version_Type is
      (case Convert_To_Protocol_Version_Type_Base (Buffer, Offset) is when 769 => TLS_1_0, when 770 => TLS_1_1, when 771 => TLS_1_2, when 772 => TLS_1_3, when others => Unreachable_Protocol_Version_Type)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Protocol_Version_Type_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Protocol_Version_Type (Buffer, Offset));

end TLS_Record;
