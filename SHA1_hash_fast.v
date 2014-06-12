module SHA1_hash_fast (       
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

parameter IDLE = 1'b0;
parameter COMPUTE = 1'b1;

integer i;

reg [31:0]		runMD[0:4], currMD[0:4], current_length, word_n, W[0:15], K_t, F_b_c_d, T;
reg [15:0]		read_addr;
reg [6:0]		count_t;
reg [1:0]		init_read;
reg				state;

wire [31:0]		word_read_n, total_length, A, B, C, D, E, W_t_next_no_shift, current_length_n, message_size_bit_s;
wire [31:0]		A_n, B_n, C_n, D_n, E_n, A_plus, B_plus, C_plus, D_plus, E_plus, BxCxD, BandC;
wire [15:0]		read_addr_n;
wire [9:0]		zero_pad_length;
wire [6:0]		count_t_n, count_t_n_mod, current_W;
wire				stop_read;




/////////ASSIGNMENTS//////////////

//INIT 
//NOTE: I think zero_pad_length is 1 more if this mod is not zero
assign zero_pad_length = 512 - ((message_size_bit_s + 65) % 512);
	//size of message + 1 + number of zeros + size of size encoding.
assign total_length = message_size_bit_s + 1 + zero_pad_length + 64;

//READ
assign read_addr_n = ((count_t > 13) & (count_t < 78) | stop_read) ? read_addr : read_addr + 4;
assign stop_read = (current_length == message_size_bit_s);
assign port_A_addr = read_addr;
assign port_A_clk = clk;
assign word_read_n = changeEndian(port_A_data_out);

//COMPUTE:
assign done = (current_length-32 == total_length) && (state == IDLE);
assign current_length_n = current_length + 32;
assign count_t_n = count_t + 1;
assign current_W = (count_t < 16) ? count_t : 15;
assign message_size_bit_s = message_size * 8;

assign A = currMD[0];
assign B = currMD[1];
assign C = currMD[2];
assign D = currMD[3];
assign E = currMD[4];

assign A_n = T;
assign B_n = A;
assign C_n = (B << 30) | (B >> 2);
assign D_n = C;
assign E_n = D;

assign A_plus = runMD[0] + A_n;
assign B_plus = runMD[1] + B_n;
assign C_plus = runMD[2] + C_n;
assign D_plus = runMD[3] + D_n;
assign E_plus = runMD[4] + E_n;

assign BxCxD = B ^ C ^ D;
assign BandC = B & C;

//storage of data optimized
assign W_t_next_no_shift = (W[13] ^ W[8] ^ W[2] ^ W[0]);

//OUT
assign hash = {runMD[0],runMD[1],runMD[2],runMD[3],runMD[4]};


always@(*)
begin
	//check which part of the buffer we want to add:
	if(current_length_n == total_length) begin
		word_n <= message_size_bit_s;
	end
	//single bit pad:
	else if((message_size - (current_length)/8 < 4)) begin
		case(message_size % 4)
		0: word_n <= 32'h80000000;
		1: word_n <= word_read_n & 32'hFF000000 | 32'h00800000;
		2: word_n <= word_read_n & 32'hFFFF0000 | 32'h00008000;
		3: word_n <= word_read_n & 32'hFFFFFF00 | 32'h00000080;
		endcase
	end
	// zero bit pads:
	else if(current_length > message_size_bit_s) begin
		word_n <= 32'h00000000;
	end
	//not doing padding, doing reads:
	else begin
		word_n <= word_read_n;
	end
	
	//compute current K_t and F_b_c_d
	if(count_t < 20) begin
		K_t <= 32'h5a827999;
		F_b_c_d <= BandC | ((~B) & D);
	end
	else if(count_t < 40) begin
		K_t <= 32'h6ed9eba1;
		F_b_c_d <= BxCxD;
	end
	else if(count_t < 60) begin
		K_t <= 32'h8f1bbcdc;
		F_b_c_d <= BandC | (B & D) | (C & D);
	end
	else begin
		K_t <= 32'hca62c1d6;
		F_b_c_d <= BxCxD;
	end
	
	//compute value of T
	T <= ((A << 5) | (A >> 27)) + F_b_c_d + W[current_W] + K_t + E;
end




//main logic:
always@(posedge clk or negedge nreset)
begin
	if(!nreset) begin
		//reset all registers
		state <=	IDLE;
		current_length <= 32'b0;
		count_t <= 7'b0;
		for(i = 0; i < 5; i = 1 + i) begin
			currMD[i] <= 32'b0;
			runMD[i] <= 32'b0;
		end
		init_read <= 2'b0;
	end
	else begin
		case(state)
			
			IDLE: begin
				if(start_hash) begin
					read_addr <= message_addr[15:0];
					state <= COMPUTE;
					init_read <= 2'b10;
					current_length <= 32'b0;
					
					//initialize to M values:
					runMD[0] <= 32'h67452301;
					runMD[1] <= 32'hefcdab89;
					runMD[2] <= 32'h98badcfe;
					runMD[3] <= 32'h10325476;
					runMD[4] <= 32'hc3d2e1f0;
					
					currMD[0] <= 32'h67452301;
					currMD[1] <= 32'hefcdab89;
					currMD[2] <= 32'h98badcfe;
					currMD[3] <= 32'h10325476;
					currMD[4] <= 32'hc3d2e1f0;
					i <= 0;
				end
			end
			COMPUTE: begin
				read_addr <= read_addr_n;
				if(!init_read) begin
					count_t <= (count_t_n == 80) ? 0 : count_t_n; //increment count_t
					//compute next W_t:
					if(count_t_n < 16) begin
						//reads:
						W[count_t_n] <= word_n;
						current_length <= current_length_n;
						i <= 0;
					end
					else begin
						W[15] <= (W_t_next_no_shift << 1) | (W_t_next_no_shift >> 31);
						
						//perform shift
						for(i=15; i > 0; i = i-1) begin
							W[i-1] <= W[i];
						end
						
					end

					if(count_t < 79) begin
						//Perform Algorithm:
						currMD[0] <= A_n;
						currMD[1] <= B_n;
						currMD[2] <= C_n;
						currMD[3] <= D_n;
						currMD[4] <= E_n;
					end
					else begin
						state <= (current_length == total_length) ? IDLE : COMPUTE;
						runMD[0] <= A_plus;
						runMD[1] <= B_plus;
						runMD[2] <= C_plus;
						runMD[3] <= D_plus;
						runMD[4] <= E_plus;
						
						currMD[0] <= A_plus;
						currMD[1] <= B_plus;
						currMD[2] <= C_plus;
						currMD[3] <= D_plus;
						currMD[4] <= E_plus;
						current_length <= current_length_n;
						W[0] <= word_n;
					end
				end
				else begin
					init_read <= init_read - 1;
					if(init_read == 2'b01) begin
						W[0] <= word_n;
						current_length <= current_length_n;
					end
				end
			end
		
		endcase
	end


end



endmodule