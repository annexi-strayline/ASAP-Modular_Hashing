------------------------------------------------------------------------------
--                                                                          --
--                        Modular Hash Infrastructure                       --
--                                                                          --
--                                SHA2 (512)                                --
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

package Modular_Hashing.SHA512 is
   
   type SHA512_Hash is new Hash with private;
   -- The final hash is a 512-bit message digest, which can also be displayed
   -- as a 128 character hex string and is 64 bytes long
   
   overriding function "<"   (Left, Right : SHA512_Hash) return Boolean;
   overriding function ">"   (Left, Right : SHA512_Hash) return Boolean;
   overriding function "="   (Left, Right : SHA512_Hash) return Boolean;
   
   SHA512_Hash_Bytes: constant := 64;
   
   overriding function Binary_Bytes (Value: SHA512_Hash) return Positive is 
     (SHA512_Hash_Bytes);
   
   overriding function Binary (Value: SHA512_Hash) return Hash_Binary_Value 
   with Post => Binary'Result'Length = SHA512_Hash_Bytes;
   
   
   
   type SHA512_Engine is new Hash_Algorithm with private;
   
   overriding 
   procedure Write (Stream : in out SHA512_Engine;
                    Item   : in     Ada.Streams.Stream_Element_Array);
   
   overriding procedure Reset  (Engine : in out SHA512_Engine);
   
   overriding function  Digest (Engine : in out SHA512_Engine)
                               return Hash'Class;
   
private
   use Ada.Streams, Interfaces;
   
   package U_128 is
      
      type Unsigned_128 is 
	 record
	    --Internal_Repr : array (1 .. 2) of Unsigned_64 := (others => 0);
	    High : Unsigned_64 := 0;
	    Low  : Unsigned_64 := 0;
	 end record;
      
      function "+" (Left, Right : Unsigned_128) return Unsigned_128;
      
   end U_128;
   
   -----------------
   -- SHA512_Hash --
   -----------------
   type Message_Digest is array (1 .. 8) of Unsigned_64;
      
   type SHA512_Hash is new Hash with
      record
         Digest: Message_Digest;
      end record;
   
   
   -------------------
   -- SHA512_Engine --
   -------------------
   -- SHA-2 Defined initialization constants
   H0_Initial: constant := 16#6a09e667f3bcc908#;
   H1_Initial: constant := 16#bb67ae8584caa73b#;
   H2_Initial: constant := 16#3c6ef372fe94f82b#;
   H3_Initial: constant := 16#a54ff53a5f1d36f1#;
   H4_Initial: constant := 16#510e527fade682d1#;
   H5_Initial: constant := 16#9b05688c2b3e6c1f#;
   H6_Initial: constant := 16#1f83d9abfb41bd6b#;
   H7_Initial: constant := 16#5be0cd19137e2179#;
   
   type K_Arr is array (1 .. 80) of Unsigned_64;
   
   K : constant K_Arr :=    
     (16#428a2f98d728ae22#, 16#7137449123ef65cd#, 16#b5c0fbcfec4d3b2f#, 16#e9b5dba58189dbbc#, 
      16#3956c25bf348b538#, 16#59f111f1b605d019#, 16#923f82a4af194f9b#, 16#ab1c5ed5da6d8118#, 
      16#d807aa98a3030242#, 16#12835b0145706fbe#, 16#243185be4ee4b28c#, 16#550c7dc3d5ffb4e2#, 
      16#72be5d74f27b896f#, 16#80deb1fe3b1696b1#, 16#9bdc06a725c71235#, 16#c19bf174cf692694#, 
      16#e49b69c19ef14ad2#, 16#efbe4786384f25e3#, 16#0fc19dc68b8cd5b5#, 16#240ca1cc77ac9c65#, 
      16#2de92c6f592b0275#, 16#4a7484aa6ea6e483#, 16#5cb0a9dcbd41fbd4#, 16#76f988da831153b5#, 
      16#983e5152ee66dfab#, 16#a831c66d2db43210#, 16#b00327c898fb213f#, 16#bf597fc7beef0ee4#, 
      16#c6e00bf33da88fc2#, 16#d5a79147930aa725#, 16#06ca6351e003826f#, 16#142929670a0e6e70#, 
      16#27b70a8546d22ffc#, 16#2e1b21385c26c926#, 16#4d2c6dfc5ac42aed#, 16#53380d139d95b3df#, 
      16#650a73548baf63de#, 16#766a0abb3c77b2a8#, 16#81c2c92e47edaee6#, 16#92722c851482353b#, 
      16#a2bfe8a14cf10364#, 16#a81a664bbc423001#, 16#c24b8b70d0f89791#, 16#c76c51a30654be30#, 
      16#d192e819d6ef5218#, 16#d69906245565a910#, 16#f40e35855771202a#, 16#106aa07032bbd1b8#, 
      16#19a4c116b8d2d0c8#, 16#1e376c085141ab53#, 16#2748774cdf8eeb99#, 16#34b0bcb5e19b48a8#, 
      16#391c0cb3c5c95a63#, 16#4ed8aa4ae3418acb#, 16#5b9cca4f7763e373#, 16#682e6ff3d6b2b8a3#, 
      16#748f82ee5defb2fc#, 16#78a5636f43172f60#, 16#84c87814a1f0ab72#, 16#8cc702081a6439ec#, 
      16#90befffa23631e28#, 16#a4506cebde82bde9#, 16#bef9a3f7b2c67915#, 16#c67178f2e372532b#, 
      16#ca273eceea26619c#, 16#d186b8c721c0c207#, 16#eada7dd6cde0eb1e#, 16#f57d4f7fee6ed178#, 
      16#06f067aa72176fba#, 16#0a637dc5a2c898a6#, 16#113f9804bef90dae#, 16#1b710b35131c471b#, 
      16#28db77f523047d84#, 16#32caab7b40c72493#, 16#3c9ebe0a15c9bebc#, 16#431d67c49c100d4c#, 
      16#4cc5d4becb3e42b6#, 16#597f299cfc657e2a#, 16#5fcb6fab3ad6faec#, 16#6c44198c4a475817#);
   
   type SHA512_Engine is new Hash_Algorithm with record
      Last_Element_Index  : Stream_Element_Offset := 0;
      Buffer              : Stream_Element_Array(1 .. 128);
        
      Message_Length      : U_128.Unsigned_128;
        
      H0                  : Unsigned_64 := H0_Initial;
      H1                  : Unsigned_64 := H1_Initial;
      H2                  : Unsigned_64 := H2_Initial;
      H3                  : Unsigned_64 := H3_Initial;
      H4                  : Unsigned_64 := H4_Initial;
      H5                  : Unsigned_64 := H5_Initial;
      H6                  : Unsigned_64 := H6_Initial;
      H7                  : Unsigned_64 := H7_Initial;
      
   end record;
   
end Modular_Hashing.SHA512;
