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
reg [31:0]		MD[0:4];
reg [15:0]		read_addr;
reg [3:0]		words_read;
reg [1:0]		state;
reg				wen, init_read;

wire [511:0]	read_hash_data_n;
wire [15:0]		read_addr_n;
wire [3:0]		words_read_n;




/////////ASSIGNMENTS//////////////

//READ
assign words_read_n = words_read + 1;
assign read_addr_n = read_addr + 4; //increment the read address

//READ/WRITE
assign port_A_addr = read_addr;
assign port_A_clk = clk;
assign read_hash_data_n = {read_hash_data[479:0],  changeEndian(port_A_data_out)}; //shift in data

//WRITE
assign port_A_we = wen;



always@(posedge clk or negedge nreset)
begin
	if(!nreset) begin
		//reset all registers
		wen <= 1'b0;
		state <=	IDLE;
		words_read <= 3'b0;
		read_hash_data <= 512'b0;
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
			end
			
			READ: begin
				read_addr <= read_addr_n;
				if(!init_read) begin
					read_hash_data <= read_hash_data_n;
					words_read <= words_read_n;
					state <= (words_read_n) ? READ : COMPUTE; //check if we have filled the buffer
				end
				else init_read <= 1'b0;
			end
			
			WRITE: begin
			
			
			end
			
			COMPUTE: begin
				state <= IDLE; //test
			
			end
		
		endcase
	end


end



endmodule