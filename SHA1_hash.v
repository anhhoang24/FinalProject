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

integer i;

reg [511:0] 	read_hash_data;
reg [31:0]		MD[0:4], current_length, byte_n;
reg [15:0]		read_addr;
reg [3:0]		words_read;
reg [1:0]		state;
reg				wen, init_read;

wire [511:0]	read_hash_data_n;
wire [31:0]		byte_read_n, total_length;
wire [15:0]		read_addr_n;
wire [9:0]		zero_pad_length;
wire [3:0]		words_read_n;




/////////ASSIGNMENTS//////////////

//INIT 
assign zero_pad_length = 512 - (((8 * message_size) + 65) % 512);
	//size of message + 1 + number of zeros + size of size encoding.
assign total_length = (message_size * 8) + 1 + zero_pad_length + 64;

//READ
assign words_read_n = words_read + 1;
assign read_addr_n = read_addr + 4; //increment the read address

//READ/WRITE
assign port_A_addr = read_addr;
assign port_A_clk = clk;
assign byte_read_n = changeEndian(port_A_data_out);
assign read_hash_data_n = {read_hash_data[479:0],  byte_n}; //shift in data
assign done = (current_length == total_length) && (state == IDLE);

//WRITE
assign port_A_we = wen;



always@(*)
begin
	//check which part of the buffer we want to add:
	if(current_length == total_length) begin
	byte_n <= {32'b0, message_size};
	end
	//single bit pad:
	else if((current_length - message_size) < 4) begin
		case(message_size % 4)
		0: byte_n <= 32'h80000000;
		1: byte_n <= byte_read_n & 32'hFF000000 | 32'h00800000;
		2: byte_n <= byte_read_n & 32'hFFFF0000 | 32'h00008000;
		3: byte_n <= byte_read_n & 32'hFFFFFF00 | 32'h00000080;
		endcase
	end
	// zero bit pads:
	else if(current_length > message_size) begin
		byte_n <= 32'h00000000;
	end
	//not doing padding, doing reads:
	else begin
		byte_n <= byte_read_n;
	end
end




//main logic:
always@(posedge clk or negedge nreset)
begin
	if(!nreset) begin
		//reset all registers
		wen <= 1'b0;
		state <=	IDLE;
		words_read <= 3'b0;
		read_hash_data <= 512'b0;
		current_length <= 32'b0;
		for(i = 0; i < 5; i = 1 + i) begin
			MD[i] <= 32'b0;
		end
		init_read <= 1'b0;
	end
	else begin
		case(state)
			
			IDLE: begin
				if(start_hash) begin
					read_addr <= message_addr[15:0];
					state <= READ;
					words_read <= 3'b0;
					read_hash_data <= 512'b0;
					init_read <= 1'b1;
					
					//initialize to M values:
					MD[0] <= 32'h67452301;
					MD[1] <= 32'hefcdab89;
					MD[2] <= 32'h98badcfe;
					MD[3] <= 32'h10325476;
					MD[4] <= 32'hc3d2e1f0;
				end
				if(wen) begin
					wen <= 1'b0;
				end
			end
			
			READ: begin
				read_addr <= read_addr_n;
				if(!init_read) begin
					read_hash_data <= read_hash_data_n;
					words_read <= words_read_n;
					state <= (words_read_n) ? READ : COMPUTE; //check if we have filled the buffer
					current_length <= current_length + 4; // keep running count of current length
				end
				else init_read <= 1'b0;
			end
			
			WRITE: begin
			
			
			end
			
			COMPUTE: begin
				state <= (current_length == total_length)? IDLE : READ; //test
			end
		
		endcase
	end


end



endmodule