module simplified_sha256 (input logic clk, reset_n, start,
                          input logic [15:0] message_addr, output_addr,
                          output logic done, mem_clk, mem_we,
								  output logic [15:0] mem_addr,
								  output logic [31:0] mem_write_data,
								  input logic [31:0] mem_read_data);
  
  // SHA256 K constants 
  parameter int sha256_k[0:63] = '{ 
     32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5, 
	  32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174, 
	  32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da, 
	  32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967, 
	  32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85, 
	  32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070, 
	  32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3, 
	  32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2 
  }; 

  // SHA256 hash round
  function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                   input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
  begin
      S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
      ch = (e & f) ^ ((~e) & g);
      t1 = h + S1 + ch + sha256_k[t] + w;
      S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
      maj = (a & b) ^ (a & c) ^ (b & c);
      t2 = S0 + maj;

      sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
  end
  endfunction

  // right rotation
  function logic [31:0] rightrotate (input logic [31:0] x,
                                     input logic [7:0] r);
  begin
    rightrotate = (x >> r) | (x << (32-r));
  end
  endfunction
  
  //define states here
  enum logic [2:0] {IDLE=3'b000, READ0=3'b001, READ1=3'b010, READ2=3'b011, BUFFER=3'b100, COMPUTE=3'b101, WRITE=3'b110, WAIT=3'b111} state;
  
  //array to hold the W_t's of M
  logic [31:0] wt[0:63];
  logic [31:0] H[0:7];
  logic [15:0] i, j, t;
  logic [31:0] s0, s1;
  logic [31:0] a, b, c, d, e, f, g, h;

  //memory clock is normal clock
  assign mem_clk = clk;
  
  
  always_ff @(posedge clk, negedge reset_n)
  begin
    if (!reset_n) begin
		i = 0;
		j = 0;
		H[0] = 32'h6a09e667;
		H[1] = 32'hbb67ae85;
	   H[2] = 32'h3c6ef372;
		H[3] = 32'ha54ff53a;
		H[4] = 32'h510e527f;
		H[5] = 32'h9b05688c;
		H[6] = 32'h1f83d9ab;
		H[7] = 32'h5be0cd19;
		done <= 0;
		state <= IDLE;
    end else
      case (state)
        IDLE:
          if (start) begin
            state <= READ0;
          end
        READ0: begin
		    mem_we <= 0;
			 mem_addr <= message_addr + i;
		    state <= READ1;
		  end
		  READ1: begin
		    state <= READ2;
		  end
		  READ2: begin
		    if( i < 16 ) wt[i] = mem_read_data;
			 else wt[i-16] = mem_read_data;
			 i++;
		    state <= READ0;
			 if( i == 16 ) state <= COMPUTE;
			 if( i == 20 ) state <= BUFFER;
		  end
		  BUFFER: begin
		    wt[4] = 32'h80000000;
			 for( i = 5; i < 15; i++ ) wt[i] = 32'h00000000;
			 wt[15] = 32'd640;
			 i <= 32;
		    state <= COMPUTE;
		  end
		  COMPUTE: begin
		    //step 4 of the slides
			 a = H[0];
			 b = H[1];
			 c = H[2];
			 d = H[3];
			 e = H[4];
			 f = H[5];
			 g = H[6];
			 h = H[7];
			 for(t = 0; t < 64; t++ ) begin
		      if( t < 16 ) begin
			     wt[t] = wt[t];
				end else begin
				  s0 = rightrotate(wt[t-15], 7) ^ rightrotate(wt[t-15], 18) ^ (wt[t-15] >> 3);
				  s1 = rightrotate(wt[t-2], 17) ^ rightrotate(wt[t-2], 19) ^ (wt[t-2] >> 10);
				  wt[t] = wt[t-16] + s0 + wt[t-7] + s1;
				end
				{a, b, c, d, e, f, g, h} = sha256_op(a, b, c, d, e, f, g, h, wt[t], t);
			 end
			 H[0] <= H[0] + a;
			 H[1] <= H[1] + b;
			 H[2] <= H[2] + c;
			 H[3] <= H[3] + d;
          H[4] <= H[4] + e;
          H[5] <= H[5] + f;
          H[6] <= H[6] + g;
          H[7] <= H[7] + h;
			 state <= READ0;
			 if( i == 32 ) state <= WRITE;
		  end
		  WRITE: begin
		    mem_we <= 1;
		    mem_addr <= output_addr + j;
			 mem_write_data <= H[j];
			 j++;
			 state <= WAIT;
		  end
		  WAIT: begin
			 if( j == 8 ) done <= 1;
		    state <= WRITE;
		  end
      endcase
  end
endmodule
