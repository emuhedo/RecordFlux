package TLS_Heartbeat.Heartbeat_Message
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Message_Type_0 (Buffer : Types.Bytes) return Boolean is
      (((Buffer'Length >= 1 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Message_Type (Buffer (Buffer'First .. Buffer'First), 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Message_Type_0 (Buffer : Types.Bytes) return Message_Type is
      (Convert_To_Message_Type (Buffer (Buffer'First .. Buffer'First), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Message_Type_0 (Buffer));

   function Valid_Message_Type (Buffer : Types.Bytes) return Boolean is
      (Valid_Message_Type_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Message_Type (Buffer : Types.Bytes) return Message_Type is
      ((if Valid_Message_Type_0 (Buffer) then Get_Message_Type_0 (Buffer) else Unreachable_Message_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Message_Type (Buffer));

   function Valid_Payload_Length_00 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Message_Type_0 (Buffer) and then ((Buffer'Length >= 3 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Convert_To_Length_Type_Base (Buffer ((Buffer'First + 1) .. (Buffer'First + 2)), 0) <= 16364)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Payload_Length_00 (Buffer : Types.Bytes) return Length_Type is
      (Convert_To_Length_Type_Base (Buffer ((Buffer'First + 1) .. (Buffer'First + 2)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload_Length_00 (Buffer));

   function Valid_Payload_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Payload_Length_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Payload_Length (Buffer : Types.Bytes) return Length_Type is
      ((if Valid_Payload_Length_00 (Buffer) then Get_Payload_Length_00 (Buffer) else Unreachable_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload_Length (Buffer));

   function Valid_Payload_000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Payload_Length_00 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Payload_Length_00 (Buffer)) + 3) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Payload_000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 3))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload_000 (Buffer));

   function Get_Payload_000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Payload_Length_00 (Buffer)) + Buffer'First + 2))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload_000 (Buffer));

   function Valid_Payload (Buffer : Types.Bytes) return Boolean is
      (Valid_Payload_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Payload_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Payload_000 (Buffer) then Get_Payload_000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload (Buffer));

   function Get_Payload_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Payload_000 (Buffer) then Get_Payload_000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload (Buffer));

   procedure Get_Payload (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Payload (Buffer)),
       Post => (First = Get_Payload_First (Buffer) and then Last = Get_Payload_Last (Buffer));

   function Valid_Padding_0000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Payload_000 (Buffer) and then Buffer'First <= (Types.Index_Type'Last / 2)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Padding_0000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Payload_Length_00 (Buffer)) + Buffer'First + 3))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Padding_0000 (Buffer));

   function Get_Padding_0000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      (Buffer'Last)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Padding_0000 (Buffer));

   function Valid_Padding (Buffer : Types.Bytes) return Boolean is
      ((Valid_Padding_0000 (Buffer) and then (((Buffer'First * (-1)) + Buffer'Last + 1) <= 16384 and then (Buffer'Last + (Types.Length_Type (Get_Payload_Length_00 (Buffer)) * (-1)) + ((-Buffer'First) / 8) + ((-23) / 8)) >= 16)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Padding_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Padding_0000 (Buffer) then Get_Padding_0000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Padding (Buffer));

   function Get_Padding_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Padding_0000 (Buffer) then Get_Padding_0000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Padding (Buffer));

   procedure Get_Padding (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Padding (Buffer)),
       Post => (First = Get_Padding_First (Buffer) and then Last = Get_Padding_Last (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      ((Valid_Padding_0000 (Buffer) and then (((Buffer'First * (-1)) + Buffer'Last + 1) <= 16384 and then (Buffer'Last + (Types.Length_Type (Get_Payload_Length_00 (Buffer)) * (-1)) + ((-Buffer'First) / 8) + ((-23) / 8)) >= 16)))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if (Valid_Padding_0000 (Buffer) and then (((Buffer'First * (-1)) + Buffer'Last + 1) <= 16384 and then (Buffer'Last + (Types.Length_Type (Get_Payload_Length_00 (Buffer)) * (-1)) + ((-Buffer'First) / 8) + ((-23) / 8)) >= 16)) then (Buffer'Last + (-Buffer'First)) else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Heartbeat.Heartbeat_Message;
