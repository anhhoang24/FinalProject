module SHA1_hash (       
	clk, 		
	nreset, 	
	start_hash,  
	message_addr,	
	message_size, 	
	hash, 	
	done, 		
	port_A_clk,
        port_A_data_in,
        port_A_data_out,
        port_A_addr,
        port_A_we
	);

input	clk;
input	nreset; 
// Initializes the SHA1_hash module

input	start_hash; 
// Tells SHA1_hash to start hashing the given frame

input 	[31:0] message_addr; 
// Starting address of the messagetext frame
// i.e., specifies from where SHA1_hash must read the messagetext frame

input	[31:0] message_size; 
// Length of the message in bytes

output	[159:0] hash; 
// hash results


input   [31:0] port_A_data_out; 
// read data from the dpsram (messagetext)

output  [31:0] port_A_data_in;
// write data to the dpsram (ciphertext)

output  [15:0] port_A_addr;
// address of dpsram being read/written 

output  port_A_clk;
// clock to dpsram (drive this with the input clk) 

output  port_A_we;
// read/write selector for dpsram

output	done; // done is a signal to indicate that hash  is complete



endmodule