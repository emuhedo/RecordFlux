with Types;
use type Types.Index_Type, Types.Length_Type;

package TLS_Heartbeat
  with SPARK_Mode
is

   type Message_Type_Base is mod (2**8);
   function Convert_To_Message_Type_Base is new Types.Convert_To_Mod (Message_Type_Base);

   type Message_Type is (HEARTBEAT_REQUEST, HEARTBEAT_RESPONSE) with Size => 8;
   for Message_Type use (HEARTBEAT_REQUEST => 1, HEARTBEAT_RESPONSE => 2);

   type Length_Type_Base is range 0 .. ((2**16) - 1) with Size => 16;
   function Convert_To_Length_Type_Base is new Types.Convert_To_Int (Length_Type_Base);

   subtype Length_Type is Length_Type_Base range 0 .. ((2**14) - 20);

   pragma Warnings (Off, "precondition is statically false");

   function Unreachable_Message_Type return Message_Type is
      (Message_Type'First)
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

   function Valid_Message_Type (Buffer : Types.Bytes; Offset : Natural) return Boolean is
      (case Convert_To_Message_Type_Base (Buffer, Offset) is when 1 | 2 => True, when others => False)
     with
       Pre => (Offset < 8 and then Buffer'Length = (((Message_Type_Base'Size + Offset + (-1)) / 8) + 1));

   function Convert_To_Message_Type (Buffer : Types.Bytes; Offset : Natural) return Message_Type is
      (case Convert_To_Message_Type_Base (Buffer, Offset) is when 1 => HEARTBEAT_REQUEST, when 2 => HEARTBEAT_RESPONSE, when others => Unreachable_Message_Type)
     with
       Pre => ((Offset < 8 and then Buffer'Length = (((Message_Type_Base'Size + Offset + (-1)) / 8) + 1)) and then Valid_Message_Type (Buffer, Offset));

end TLS_Heartbeat;
