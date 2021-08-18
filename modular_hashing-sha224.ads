------------------------------------------------------------------------------
--                                                                          --
--                        Modular Hash Infrastructure                       --
--                                                                          --
--                                SHA2 (224)                                --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2019-2021, ANNEXI-STRAYLINE Trans-Human Ltd.              --
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

package Modular_Hashing.SHA224 is
   
   type SHA224_Hash is new Hash with private;
   -- The final hash is a 256-bit message digest, which can also be displayed
   -- as a 56 character hex string and is 28 bytes long
   
   overriding function "<"   (Left, Right : SHA224_Hash) return Boolean;
   overriding function ">"   (Left, Right : SHA224_Hash) return Boolean;
   overriding function "="   (Left, Right : SHA224_Hash) return Boolean;
   
   SHA224_Hash_Bytes: constant := 28;
   
   overriding function Binary_Bytes (Value: SHA224_Hash) return Positive is 
     (SHA224_Hash_Bytes);
   
   overriding function Binary (Value: SHA224_Hash) return Hash_Binary_Value 
   with Post => Binary'Result'Length = SHA224_Hash_Bytes;
   
   
   
   type SHA224_Engine is new Hash_Algorithm with private;
   
   overriding 
   procedure Write (Stream : in out SHA224_Engine;
                    Item   : in     Ada.Streams.Stream_Element_Array);
   
   overriding procedure Reset  (Engine : in out SHA224_Engine);
   
   overriding function  Digest (Engine : in out SHA224_Engine)
                               return Hash'Class;
   
private
   use Ada.Streams, Interfaces;
   
   -----------------
   -- SHA224_Hash --
   -----------------
   type Message_Digest is array (1 .. 8) of Unsigned_32;
      
   type SHA224_Hash is new Hash with
      record
         Digest: Message_Digest;
      end record;
   
   
   -----------------
   -- SHA224_Engine --
   -----------------
   -- SHA-2 Defined initialization constants
   H0_Initial: constant := 16#c1059ed8#;
   H1_Initial: constant := 16#367cd507#;
   H2_Initial: constant := 16#3070dd17#;
   H3_Initial: constant := 16#f70e5939#;
   H4_Initial: constant := 16#ffc00b31#;
   H5_Initial: constant := 16#68581511#;
   H6_Initial: constant := 16#64f98fa7#;
   H7_Initial: constant := 16#befa4fa4#;

   type K_Arr is array (1 .. 64) of Unsigned_32;
   
   K : constant K_Arr := 
     (16#428a2f98#, 16#71374491#, 16#b5c0fbcf#, 16#e9b5dba5#, 
      16#3956c25b#, 16#59f111f1#, 16#923f82a4#, 16#ab1c5ed5#,
      16#d807aa98#, 16#12835b01#, 16#243185be#, 16#550c7dc3#, 
      16#72be5d74#, 16#80deb1fe#, 16#9bdc06a7#, 16#c19bf174#,
      16#e49b69c1#, 16#efbe4786#, 16#0fc19dc6#, 16#240ca1cc#, 
      16#2de92c6f#, 16#4a7484aa#, 16#5cb0a9dc#, 16#76f988da#,
      16#983e5152#, 16#a831c66d#, 16#b00327c8#, 16#bf597fc7#, 
      16#c6e00bf3#, 16#d5a79147#, 16#06ca6351#, 16#14292967#,
      16#27b70a85#, 16#2e1b2138#, 16#4d2c6dfc#, 16#53380d13#, 
      16#650a7354#, 16#766a0abb#, 16#81c2c92e#, 16#92722c85#,
      16#a2bfe8a1#, 16#a81a664b#, 16#c24b8b70#, 16#c76c51a3#, 
      16#d192e819#, 16#d6990624#, 16#f40e3585#, 16#106aa070#,
      16#19a4c116#, 16#1e376c08#, 16#2748774c#, 16#34b0bcb5#,
      16#391c0cb3#, 16#4ed8aa4a#, 16#5b9cca4f#, 16#682e6ff3#,
      16#748f82ee#, 16#78a5636f#, 16#84c87814#, 16#8cc70208#,
      16#90befffa#, 16#a4506ceb#, 16#bef9a3f7#, 16#c67178f2#);
   
   type SHA224_Engine is new Hash_Algorithm with record
      Last_Element_Index  : Stream_Element_Offset := 0;
      Buffer              : Stream_Element_Array(1 .. 64);
        
      Message_Length      : Unsigned_64 := 0;
        
      H0                  : Unsigned_32 := H0_Initial;
      H1                  : Unsigned_32 := H1_Initial;
      H2                  : Unsigned_32 := H2_Initial;
      H3                  : Unsigned_32 := H3_Initial;
      H4                  : Unsigned_32 := H4_Initial;
      H5                  : Unsigned_32 := H5_Initial;
      H6                  : Unsigned_32 := H6_Initial;
      H7                  : Unsigned_32 := H7_Initial;
      
   end record;
   
end Modular_Hashing.SHA224;
