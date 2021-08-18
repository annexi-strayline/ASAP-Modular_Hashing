------------------------------------------------------------------------------
--                                                                          --
--                        Modular Hash Infrastructure                       --
--                                                                          --
--                               Version 1.0                                --
--                                                                          --
-- ------------------------------------------------------------------------ --
--                                                                          --
--  Copyright (C) 2018-2019, ANNEXI-STRAYLINE Trans-Human Ltd.              --
--  All rights reserved.                                                    --
--                                                                          --
--  Original Contributors:                                                  --
--  * Richard Wai, Ensi Martini, Aninda Poddar, Noshen Atashe               --
--    (ANNEXI-STRAYLINE)                                                    --
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

with Hex.Unsigned_8;

package body Modular_Hashing is
   
   -----------------
   -- Hexadecimal --
   -----------------
   
   function  Hexadecimal (Value     : Hash; 
                          Lower_Case: Boolean := True) 
                         return String 
   is
      Bin: constant Hash_Binary_Value := Hash'Class (Value).Binary;
      I: Positive;
   begin
      return Result: String (1 .. Value.Hexadecimal_Digits) do
         pragma Assert (Bin'Length * 2 = Result'Length);
         
         -- Assuming little endian
         I := Result'Last + 2;
         
         for Byte of Bin loop
            I := I - 2;
            
            Hex.Unsigned_8.Encode
              (Value    => Byte, 
               Buffer   => Result(I - 1 .. I),
               Use_Case => (if Lower_Case then Hex.Lower_Case 
                            else Hex.Upper_Case));

         end loop;
         
         pragma Assert (I = Result'First + 1);
      end return;
   end Hexadecimal;
   
   ----------
   -- Read --
   ----------
   
   procedure Read (Stream: in out Hash_Algorithm;
                   Item  :    out Ada.Streams.Stream_Element_Array;
                   Last  :    out Ada.Streams.Stream_Element_Offset)
   is
   begin
      raise Program_Error;
   end Read;
   
   ------------
   -- Digest --
   ------------
   function  Digest (Engine : in out Hash_Algorithm'Class;
                     Message: in     String) 
                    return Hash'Class
   is begin
      String'Write (Engine'Access, Message);
      return Hash_Algorithm'Class(Engine).Digest;
   end Digest;
   
   
   ----------------------------------------------------------------------------
   function  Digest (Engine : in out Hash_Algorithm'Class;
                     Message: in     Wide_String) 
                    return Hash'Class
   is begin
      Wide_String'Write (Engine'Access, Message);
      return Hash_Algorithm'Class(Engine).Digest;
   end Digest;
   
   
   ----------------------------------------------------------------------------
   function  Digest (Engine : in out Hash_Algorithm'Class;
                     Message: in     Wide_Wide_String) 
                    return Hash'Class
   is begin
      Wide_Wide_String'Write (Engine'Access, Message);
      return Hash_Algorithm'Class(Engine).Digest;
   end Digest;
   
end Modular_Hashing;
