package TLS_Handshake.New_Session_Ticket
  with SPARK_Mode
is

   function Is_Contained (Buffer : Types.Bytes) return Boolean
     with
       Ghost,
       Import;

   procedure Label (Buffer : Types.Bytes)
     with
       Post => Is_Contained (Buffer);

   function Valid_Ticket_Lifetime_0 (Buffer : Types.Bytes) return Boolean is
      ((Buffer'Length >= 4 and then Buffer'First <= (Types.Index_Type'Last / 2)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Lifetime_0 (Buffer : Types.Bytes) return Ticket_Lifetime_Type is
      (Convert_To_Ticket_Lifetime_Type (Buffer (Buffer'First .. (Buffer'First + 3)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Lifetime_0 (Buffer));

   function Valid_Ticket_Lifetime (Buffer : Types.Bytes) return Boolean is
      (Valid_Ticket_Lifetime_0 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Lifetime (Buffer : Types.Bytes) return Ticket_Lifetime_Type is
      ((if Valid_Ticket_Lifetime_0 (Buffer) then Get_Ticket_Lifetime_0 (Buffer) else Unreachable_Ticket_Lifetime_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Lifetime (Buffer));

   function Valid_Ticket_Age_Add_00 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Ticket_Lifetime_0 (Buffer) and then (Buffer'Length >= 8 and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Age_Add_00 (Buffer : Types.Bytes) return Ticket_Age_Add_Type is
      (Convert_To_Ticket_Age_Add_Type (Buffer ((Buffer'First + 4) .. (Buffer'First + 7)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Age_Add_00 (Buffer));

   function Valid_Ticket_Age_Add (Buffer : Types.Bytes) return Boolean is
      (Valid_Ticket_Age_Add_00 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Age_Add (Buffer : Types.Bytes) return Ticket_Age_Add_Type is
      ((if Valid_Ticket_Age_Add_00 (Buffer) then Get_Ticket_Age_Add_00 (Buffer) else Unreachable_Ticket_Age_Add_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Age_Add (Buffer));

   function Valid_Ticket_Nonce_Length_000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Ticket_Age_Add_00 (Buffer) and then (Buffer'Length >= 9 and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Nonce_Length_000 (Buffer : Types.Bytes) return Ticket_Nonce_Length_Type is
      (Convert_To_Ticket_Nonce_Length_Type (Buffer ((Buffer'First + 8) .. (Buffer'First + 8)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Nonce_Length_000 (Buffer));

   function Valid_Ticket_Nonce_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Ticket_Nonce_Length_000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Nonce_Length (Buffer : Types.Bytes) return Ticket_Nonce_Length_Type is
      ((if Valid_Ticket_Nonce_Length_000 (Buffer) then Get_Ticket_Nonce_Length_000 (Buffer) else Unreachable_Ticket_Nonce_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Nonce_Length (Buffer));

   function Valid_Ticket_Nonce_0000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Ticket_Nonce_Length_000 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + 9) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Nonce_0000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Buffer'First + 9))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Nonce_0000 (Buffer));

   function Get_Ticket_Nonce_0000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 8))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Nonce_0000 (Buffer));

   function Valid_Ticket_Nonce (Buffer : Types.Bytes) return Boolean is
      (Valid_Ticket_Nonce_0000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Nonce_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Ticket_Nonce_0000 (Buffer) then Get_Ticket_Nonce_0000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Nonce (Buffer));

   function Get_Ticket_Nonce_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Ticket_Nonce_0000 (Buffer) then Get_Ticket_Nonce_0000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Nonce (Buffer));

   procedure Get_Ticket_Nonce (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Nonce (Buffer)),
       Post => (First = Get_Ticket_Nonce_First (Buffer) and then Last = Get_Ticket_Nonce_Last (Buffer));

   function Valid_Ticket_Length_00000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Ticket_Nonce_0000 (Buffer) and then ((Buffer'Length >= (Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + 11) and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Convert_To_Ticket_Length_Type_Base (Buffer ((Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 9) .. (Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 10)), 0) >= 1)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Length_00000 (Buffer : Types.Bytes) return Ticket_Length_Type is
      (Convert_To_Ticket_Length_Type_Base (Buffer ((Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 9) .. (Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 10)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Length_00000 (Buffer));

   function Valid_Ticket_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Ticket_Length_00000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_Length (Buffer : Types.Bytes) return Ticket_Length_Type is
      ((if Valid_Ticket_Length_00000 (Buffer) then Get_Ticket_Length_00000 (Buffer) else Unreachable_Ticket_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_Length (Buffer));

   function Valid_Ticket_000000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Ticket_Length_00000 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + 11) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_000000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 11))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_000000 (Buffer));

   function Get_Ticket_000000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 10))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket_000000 (Buffer));

   function Valid_Ticket (Buffer : Types.Bytes) return Boolean is
      (Valid_Ticket_000000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Ticket_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Ticket_000000 (Buffer) then Get_Ticket_000000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket (Buffer));

   function Get_Ticket_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Ticket_000000 (Buffer) then Get_Ticket_000000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket (Buffer));

   procedure Get_Ticket (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Ticket (Buffer)),
       Post => (First = Get_Ticket_First (Buffer) and then Last = Get_Ticket_Last (Buffer));

   function Valid_Extensions_Length_0000000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Ticket_000000 (Buffer) and then ((Buffer'Length >= (Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + 13) and then Buffer'First <= (Types.Index_Type'Last / 2)) and then Convert_To_New_Session_Ticket_Extensions_Length_Type_Base (Buffer ((Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 11) .. (Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 12)), 0) <= 65534)))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_Length_0000000 (Buffer : Types.Bytes) return New_Session_Ticket_Extensions_Length_Type is
      (Convert_To_New_Session_Ticket_Extensions_Length_Type_Base (Buffer ((Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 11) .. (Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 12)), 0))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_Length_0000000 (Buffer));

   function Valid_Extensions_Length (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_Length_0000000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_Length (Buffer : Types.Bytes) return New_Session_Ticket_Extensions_Length_Type is
      ((if Valid_Extensions_Length_0000000 (Buffer) then Get_Extensions_Length_0000000 (Buffer) else Unreachable_New_Session_Ticket_Extensions_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_Length (Buffer));

   function Valid_Extensions_00000000 (Buffer : Types.Bytes) return Boolean is
      ((Valid_Extensions_Length_0000000 (Buffer) and then (Buffer'Length >= (Types.Length_Type (Get_Extensions_Length_0000000 (Buffer)) + Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + 13) and then Buffer'First <= (Types.Index_Type'Last / 2))))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_00000000_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 13))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_00000000 (Buffer));

   function Get_Extensions_00000000_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((Types.Length_Type (Get_Extensions_Length_0000000 (Buffer)) + Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + Buffer'First + 12))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions_00000000 (Buffer));

   function Valid_Extensions (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_00000000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Get_Extensions_First (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Extensions_00000000 (Buffer) then Get_Extensions_00000000_First (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer));

   function Get_Extensions_Last (Buffer : Types.Bytes) return Types.Index_Type is
      ((if Valid_Extensions_00000000 (Buffer) then Get_Extensions_00000000_Last (Buffer) else Unreachable_Types_Index_Type))
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer));

   procedure Get_Extensions (Buffer : Types.Bytes; First : out Types.Index_Type; Last : out Types.Index_Type)
     with
       Pre => (Is_Contained (Buffer) and then Valid_Extensions (Buffer)),
       Post => (First = Get_Extensions_First (Buffer) and then Last = Get_Extensions_Last (Buffer));

   function Is_Valid (Buffer : Types.Bytes) return Boolean is
      (Valid_Extensions_00000000 (Buffer))
     with
       Pre => Is_Contained (Buffer);

   function Message_Length (Buffer : Types.Bytes) return Types.Length_Type is
      ((if Valid_Extensions_00000000 (Buffer) then (Types.Length_Type (Get_Extensions_Length_0000000 (Buffer)) + Types.Length_Type (Get_Ticket_Length_00000 (Buffer)) + Types.Length_Type (Get_Ticket_Nonce_Length_000 (Buffer)) + 13) else Unreachable_Types_Length_Type))
     with
       Pre => (Is_Contained (Buffer) and then Is_Valid (Buffer));

end TLS_Handshake.New_Session_Ticket;
