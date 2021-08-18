------------------------------------------------------------------------------
--                                                                          --
--                        Modular Hash Infrastructure                       --
--                                                                          --
--                                   SHA1                                   --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2018-2021, ANNEXI-STRAYLINE Trans-Human Ltd.              --
--  All rights reserved.                                                    --
--                                                                          --
--  Original Contributors:                                                  --
--  * Ensi Martini (ANNEXI-STRAYLINE)                                       --
--                                                                          --
--  Redistribution and use in source and binary forms, with or without      --
--  modification, are permitted provided that the following conditions are  --
--  met:                                                                    --
--                                                                          --
--      * Redistributions of source code must retain the above copyright    --
--        notice, this list of conditions and the following disclaimer.     --
--                                                                          --
--      * Redistributions in binary form must reproduce the above copyright --
--        notice, this list of conditions and the following disclaimer in   --
--        the documentation and/or other materials provided with the        --
--        distribution.                                                     --
--                                                                          --
--      * Neither the name of the copyright holder nor the names of its     --
--        contributors may be used to endorse or promote products derived   --
--        from this software without specific prior written permission.     --
--                                                                          --
--  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS     --
--  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT       --
--  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A --
--  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT      --
--  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,   --
--  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT        --
--  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,   --
--  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY   --
--  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT     --
--  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   --
--  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.    --
--                                                                          --
------------------------------------------------------------------------------


with Interfaces;
with Ada.Streams;

package Modular_Hashing.SHA1 is
   
   type SHA1_Hash is new Hash with private;
   -- The final hash is a 160-bit message digest, which can also be displayed
   -- as a 40 character hex string and is 20 bytes long
   
   overriding function "<"   (Left, Right : SHA1_Hash) return Boolean;
   overriding function ">"   (Left, Right : SHA1_Hash) return Boolean;
   overriding function "="   (Left, Right : SHA1_Hash) return Boolean;
   
   SHA1_Hash_Bytes: constant := 20;
   
   overriding function Binary_Bytes (Value: SHA1_Hash) return Positive is 
     (SHA1_Hash_Bytes);
   
   overriding function Binary (Value: SHA1_Hash) return Hash_Binary_Value with
     Post => Binary'Result'Length = SHA1_Hash_Bytes;
   
   
   type SHA1_Engine is new Hash_Algorithm with private;
   
   overriding 
   procedure Write (Stream : in out SHA1_Engine;
                    Item   : in     Ada.Streams.Stream_Element_Array);
   
   overriding procedure Reset  (Engine : in out SHA1_Engine);
   
   overriding function  Digest (Engine : in out SHA1_Engine)
                               return Hash'Class;
   
private
   use Ada.Streams, Interfaces;
   
   type Message_Digest is array (1 .. 5) of Unsigned_32;
      
   type SHA1_Hash is new Hash with
      record
         Digest: Message_Digest;
      end record;
   
   
   -----------------
   -- SHA1_Engine --
   -----------------
   -- SHA-1 Defined initialization constants
   H0_Initial: constant := 16#67452301#;
   H1_Initial: constant := 16#EFCDAB89#;
   H2_Initial: constant := 16#98BADCFE#;
   H3_Initial: constant := 16#10325476#;
   H4_Initial: constant := 16#C3D2E1F0#;
   
   type SHA1_Engine is new Hash_Algorithm with record
      Last_Element_Index  : Stream_Element_Offset := 0;
      Buffer              : Stream_Element_Array(1 .. 64);
        
      Message_Length      : Unsigned_64 := 0;
        
      H0                  : Unsigned_32 := H0_Initial;
      H1                  : Unsigned_32 := H1_Initial;
      H2                  : Unsigned_32 := H2_Initial;
      H3                  : Unsigned_32 := H3_Initial;
      H4                  : Unsigned_32 := H4_Initial;
   end record;
   
end Modular_Hashing.SHA1;
