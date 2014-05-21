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
	
//define endian switch function:
function [31:0] changeEndian;
		input [31:0] value;
		changeEndian = { value[7:0], value[15:8], value[23:16], value[31:24]};
endfunction
		
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

parameter IDLE = 2'b00;
parameter READ = 2'b01;
parameter WRITE = 2'b10;
parameter COMPUTE = 2'b11;

reg [159:0] 	read_hash_data;
reg [15:0]		read_addr;
reg [2:0]		words_read;
reg [1:0]		state;
reg				wen;

wire [159:0]	read_hash_data_n;
wire [15:0]		read_addr_n;
wire [2:0]		words_read_n;




/////////ASSIGNMENTS//////////////

//READ
assign words_read_n = words_read + 1;

//READ/WRITE
assign port_A_addr = read_addr;
assign port_A_clk = clk;
assign read_hash_data_n = {read_hash_data[127:0],  changeEndian(port_A_data_out)}; //shift in data

//WRITE
assign port_A_we = wen;



always@(posedge clk or negedge nreset)
begin
	if(!nreset) begin
		//reset all registers
		wen <= 1'b0;
		state <=	IDLE;
		words_read <= 3'b0;
		read_hash_data <= 160'b0;
	end
	else begin
		case(state)
			
			IDLE: begin
				if(start_hash) begin
					read_addr <= message_addr[15:0];
					state <= READ;
					words_read <= 3'b0;
					read_hash_data <= 160'b0;
				end
			end
			
			READ: begin
				read_addr <= read_addr_n;
				//TODO: I think I am reading the data wrong. should be 512 instead of 160
				read_hash_data <= read_hash_data_n;
				words_read <= 3'b0;
			end
			
			WRITE: begin
			
			
			end
			
			COMPUTE: begin
			
			
			end
		
		endcase
	end


end



endmodule