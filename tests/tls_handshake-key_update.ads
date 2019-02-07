package TLS_Handshake.Key_Update
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Request_Update_0 (Buffer : Types.Bytes) return Boolean is
      (((Buffer'Length >= 1 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Key_Update_Request (Buffer (Buffer'First .. Buffer'First), 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Request_Update_0 (Buffer : Types.Bytes) return Key_Update_Request is
      (Convert_To_Key_Update_Request (Buffer (Buffer'First .. Buffer'First), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Request_Update_0 (Buffer));

   function Valid_Request_Update (Buffer : Types.Bytes) return Boolean is
      (Valid_Request_Update_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Request_Update (Buffer : Types.Bytes) return Key_Update_Request is
      ((if Valid_Request_Update_0 (Buffer) then Get_Request_Update_0 (Buffer) else Unreachable_Key_Update_Request))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Request_Update (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Request_Update_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Request_Update_0 (Buffer) then 1 else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Handshake.Key_Update;
