# CSpawn_Assembly

-	adding a procedure (using near pointers) to CSpawn (companion virus) which will demand a password before executing the host

First of all I hardcoded the required password in a byte-level variable and created the given password variable with many uninitialized bytes.
I used a procedure with the offsets (addresses) of each password in the data segment, pushed on stack, so I can work with near pointers pointing at the beginning of each string. 
This procedure will read from input and will compare each character with returning a result on a register (DX).After calling the procedure and "releasing" the memory, I will check with DX if the virus got the right password (continue in executing the host ) or not (exit code). 
