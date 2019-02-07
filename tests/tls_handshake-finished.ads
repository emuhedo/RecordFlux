package TLS_Handshake.Finished
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Verify_Data_0 (Buffer : Types.Bytes) return Boolean is
      (Buffer'First <= (Types.Index_Type'Last / 2))
     with
       Pre => Is_Contained (Buffer);

   function Get_Verify_Data_0_First (Buffer : Types.Bytes) return Types.Index_Type is
      (Buffer'First)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Verify_Data_0 (Buffer));

   function Get_Verify_Data_0_Last (Buffer : Types.Bytes) return Types.Index_Type is
      (Buffer'Last)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Verify_Data_0 (Buffer));

   function Valid_Verify_Data (Buffer : Types.Bytes) return Boolean is
      (Valid_Verify_Data_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Verify_Data_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Verify_Data_0 (Buffer) then Get_Verify_Data_0_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Verify_Data (Buffer));

   function Get_Verify_Data_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Verify_Data_0 (Buffer) then Get_Verify_Data_0_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Verify_Data (Buffer));

   procedure Get_Verify_Data (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Verify_Data (Buffer)),
       Post => (First = Get_Verify_Data_First (Buffer) and then Last = Get_Verify_Data_Last (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Verify_Data_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Verify_Data_0 (Buffer) then ((Buffer'First * (-1)) + Buffer'Last + 1) else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Handshake.Finished;
