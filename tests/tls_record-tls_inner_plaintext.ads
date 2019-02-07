package TLS_Record.TLS_Inner_Plaintext
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Tag_0 (Buffer : Types.Bytes) return Boolean is
      (((Buffer'Length >= 1 and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Valid_Content_Type (Buffer (Buffer'First .. Buffer'First), 0)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Tag_0 (Buffer : Types.Bytes) return Content_Type is
      (Convert_To_Content_Type (Buffer (Buffer'First .. Buffer'First), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Tag_0 (Buffer));

   function Valid_Tag (Buffer : Types.Bytes) return Boolean is
      (Valid_Tag_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Tag (Buffer : Types.Bytes) return Content_Type is
      ((if Valid_Tag_0 (Buffer) then Get_Tag_0 (Buffer) else Unreachable_Content_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Tag (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Tag_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Tag_0 (Buffer) then 1 else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Record.TLS_Inner_Plaintext;
