// SHA-256 Verilog Implementation

module right_rotate #(
    parameter WIDTH = 32
)(
    input  wire [WIDTH-1:0] x,   // Input value to rotate
    input  wire [$clog2(WIDTH)-1:0] n, // Number of bits to rotate by
    output wire [WIDTH-1:0] y    // Rotated result
);
    assign y = (x >> n) | (x << (WIDTH - n));
endmodule

module sigma_0(
    input wire [31:0] x,
    output wire [31:0] sigma0
);
    wire [31:0] a, b, c;
    right_rotate #(.WIDTH(32)) r1(.x(x), .n(5'd7), .y(a));
    right_rotate #(.WIDTH(32)) r2(.x(x), .n(5'd18), .y(b));
    assign c = x >> 3;
    assign sigma0 = a ^ b ^ c;
endmodule

module sigma_1(
    input wire [31:0] x,
    output wire [31:0] sigma1
);
    wire [31:0] a, b, c;
    right_rotate #(.WIDTH(32)) r1(.x(x), .n(5'd17), .y(a));
    right_rotate #(.WIDTH(32)) r2(.x(x), .n(5'd19), .y(b));
    assign c = x >> 10;
    assign sigma1 = a ^ b ^ c;
endmodule

module big_sigma_0(
    input wire [31:0] x,
    output wire [31:0] big_sigma0
);
    wire [31:0] a, b, c;
    right_rotate #(.WIDTH(32)) r1(.x(x), .n(5'd2), .y(a));
    right_rotate #(.WIDTH(32)) r2(.x(x), .n(5'd13), .y(b));
    right_rotate #(.WIDTH(32)) r3(.x(x), .n(5'd22), .y(c));
    assign big_sigma0 = a ^ b ^ c;
endmodule

module big_sigma_1(
    input wire [31:0] x,
    output wire [31:0] big_sigma1
);
    wire [31:0] a, b, c;
    right_rotate #(.WIDTH(32)) r1(.x(x), .n(5'd6), .y(a));
    right_rotate #(.WIDTH(32)) r2(.x(x), .n(5'd11), .y(b));
    right_rotate #(.WIDTH(32)) r3(.x(x), .n(5'd25), .y(c));
    assign big_sigma1 = a ^ b ^ c;
endmodule

module choice(
    input wire [31:0] x,
    input wire [31:0] y, 
    input wire [31:0] z, 
    output wire [31:0] ch
);
    assign ch = (x & y) ^ (~x & z);
endmodule

module majority(
    input wire [31:0] x,
    input wire [31:0] y, 
    input wire [31:0] z, 
    output wire [31:0] maj
);
    assign maj = (x & y) ^ (x & z) ^ (y & z);
endmodule

module sha256_core(
    input wire clk,
    input wire rst,
    input wire [7:0] message_byte,
    input wire message_valid,
    input wire message_last,
    output reg hash_valid,
    output reg [255:0] hash_value
);

    // Constants - SHA-256 initial hash values H (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    localparam [31:0] H0 = 32'h6a09e667;
    localparam [31:0] H1 = 32'hbb67ae85;
    localparam [31:0] H2 = 32'h3c6ef372;
    localparam [31:0] H3 = 32'ha54ff53a;
    localparam [31:0] H4 = 32'h510e527f;
    localparam [31:0] H5 = 32'h9b05688c;
    localparam [31:0] H6 = 32'h1f83d9ab;
    localparam [31:0] H7 = 32'h5be0cd19;

    // Round constants K (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
    reg [31:0] K [0:63];
    
    // Initialize round constants
    initial begin
        K[0] = 32'h428a2f98; K[1] = 32'h71374491; K[2] = 32'hb5c0fbcf; K[3] = 32'he9b5dba5;
        K[4] = 32'h3956c25b; K[5] = 32'h59f111f1; K[6] = 32'h923f82a4; K[7] = 32'hab1c5ed5;
        K[8] = 32'hd807aa98; K[9] = 32'h12835b01; K[10] = 32'h243185be; K[11] = 32'h550c7dc3;
        K[12] = 32'h72be5d74; K[13] = 32'h80deb1fe; K[14] = 32'h9bdc06a7; K[15] = 32'hc19bf174;
        K[16] = 32'he49b69c1; K[17] = 32'hefbe4786; K[18] = 32'h0fc19dc6; K[19] = 32'h240ca1cc;
        K[20] = 32'h2de92c6f; K[21] = 32'h4a7484aa; K[22] = 32'h5cb0a9dc; K[23] = 32'h76f988da;
        K[24] = 32'h983e5152; K[25] = 32'ha831c66d; K[26] = 32'hb00327c8; K[27] = 32'hbf597fc7;
        K[28] = 32'hc6e00bf3; K[29] = 32'hd5a79147; K[30] = 32'h06ca6351; K[31] = 32'h14292967;
        K[32] = 32'h27b70a85; K[33] = 32'h2e1b2138; K[34] = 32'h4d2c6dfc; K[35] = 32'h53380d13;
        K[36] = 32'h650a7354; K[37] = 32'h766a0abb; K[38] = 32'h81c2c92e; K[39] = 32'h92722c85;
        K[40] = 32'ha2bfe8a1; K[41] = 32'ha81a664b; K[42] = 32'hc24b8b70; K[43] = 32'hc76c51a3;
        K[44] = 32'hd192e819; K[45] = 32'hd6990624; K[46] = 32'hf40e3585; K[47] = 32'h106aa070;
        K[48] = 32'h19a4c116; K[49] = 32'h1e376c08; K[50] = 32'h2748774c; K[51] = 32'h34b0bcb5;
        K[52] = 32'h391c0cb3; K[53] = 32'h4ed8aa4a; K[54] = 32'h5b9cca4f; K[55] = 32'h682e6ff3;
        K[56] = 32'h748f82ee; K[57] = 32'h78a5636f; K[58] = 32'h84c87814; K[59] = 32'h8cc70208;
        K[60] = 32'h90befffa; K[61] = 32'ha4506ceb; K[62] = 32'hbef9a3f7; K[63] = 32'hc67178f2;
    end

    // State definitions
    localparam STATE_IDLE = 3'd0;
    localparam STATE_LOAD_MESSAGE = 3'd1;
    localparam STATE_PAD_MESSAGE = 3'd2;
    localparam STATE_PREPARE_SCHEDULE = 3'd3;
    localparam STATE_COMPRESS = 3'd4;
    localparam STATE_FINALIZE = 3'd5;

    // State register
    reg [2:0] state;
    reg [2:0] next_state;

    // Message buffer (512-bit block)
    reg [7:0] message_block [0:63];
    reg [6:0] message_block_index;
    reg [63:0] message_length_bits;

    // Message schedule (W array)
    reg [31:0] W [0:63];
    reg [5:0] schedule_index;

    // Hash state
    reg [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
    reg [31:0] a, b, c, d, e, f, g, h;
    reg [5:0] compression_index;
    reg padding_done;
    reg [31:0] temp1, temp2;
    
    // Wires for compression function
    wire [31:0] ch_out, maj_out, sig0_out, sig1_out;

    // Instantiate hash function modules
    choice ch_inst(
        .x(e),
        .y(f),
        .z(g),
        .ch(ch_out)
    );

    majority maj_inst(
        .x(a),
        .y(b),
        .z(c),
        .maj(maj_out)
    );

    big_sigma_0 sig0_inst(
        .x(a),
        .big_sigma0(sig0_out)
    );

    big_sigma_1 sig1_inst(
        .x(e),
        .big_sigma1(sig1_out)
    );

    // State machine
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            state <= STATE_IDLE;
        end else begin
            state <= next_state;
        end
    end

    // Next state logic
    always @(*) begin
        next_state = state;
        
        case (state)
            STATE_IDLE: begin
                if (message_valid)
                    next_state = STATE_LOAD_MESSAGE;
            end
            
            STATE_LOAD_MESSAGE: begin
                if (message_last && message_valid)
                    next_state = STATE_PAD_MESSAGE;
            end
            
            STATE_PAD_MESSAGE: begin
                if (padding_done)
                    next_state = STATE_PREPARE_SCHEDULE;
            end
            
            STATE_PREPARE_SCHEDULE: begin
                if (schedule_index == 63)
                    next_state = STATE_COMPRESS;
            end
            
            STATE_COMPRESS: begin
                if (compression_index == 63)
                    next_state = STATE_FINALIZE;
            end
            
            STATE_FINALIZE: begin
                next_state = STATE_IDLE;
            end
        endcase
    end

    // Process logic
    always @(posedge clk) begin
        if (rst) begin
            // Reset all registers
            h0 <= H0; h1 <= H1; h2 <= H2; h3 <= H3;
            h4 <= H4; h5 <= H5; h6 <= H6; h7 <= H7;
            message_block_index <= 0;
            message_length_bits <= 0;
            schedule_index <= 0;
            compression_index <= 0;
            padding_done <= 0;
            hash_valid <= 0;
            hash_value <= 256'h0;
        end else begin
            case (state)
                STATE_IDLE: begin
                    if (message_valid) begin
                        // Initialize hash values
                        h0 <= H0; h1 <= H1; h2 <= H2; h3 <= H3;
                        h4 <= H4; h5 <= H5; h6 <= H6; h7 <= H7;
                        message_block_index <= 0;
                        message_length_bits <= 0;
                        hash_valid <= 0;
                    end
                end
                
                STATE_LOAD_MESSAGE: begin
                    if (message_valid) begin
                        message_block[message_block_index] <= message_byte;
                        message_block_index <= message_block_index + 1;
                        message_length_bits <= message_length_bits + 8;
                        
                        // If block is full, process it
                        if (message_block_index == 63) begin
                            message_block_index <= 0;
                            schedule_index <= 0;
                        end
                    end
                end
                
                STATE_PAD_MESSAGE: begin
                    if (!padding_done) begin
                        // Add padding
                        // 1. Append a '1' bit
                        message_block[message_block_index] <= 8'h80;
                        message_block_index <= message_block_index + 1;
                        
                        // 2. Append '0' bits until message length is 448 bits mod 512
                        if (message_block_index < 56) begin
                            // We have room for length in this block
                            message_block_index <= 56;  // Jump to length field
                        end else begin
                            // Fill this block with zeros
                            message_block_index <= message_block_index + 1;
                            if (message_block_index == 63) begin
                                message_block_index <= 0;
                                // Process the first padded block
                                schedule_index <= 0;
                            end
                        end
                        
                        // 3. Append length as 64-bit big-endian integer
                        if (message_block_index == 56) begin
                            message_block[56] <= message_length_bits[63:56];
                            message_block[57] <= message_length_bits[55:48];
                            message_block[58] <= message_length_bits[47:40];
                            message_block[59] <= message_length_bits[39:32];
                            message_block[60] <= message_length_bits[31:24];
                            message_block[61] <= message_length_bits[23:16];
                            message_block[62] <= message_length_bits[15:8];
                            message_block[63] <= message_length_bits[7:0];
                            padding_done <= 1;
                        end
                    end
                end
                
                STATE_PREPARE_SCHEDULE: begin
                    if (schedule_index < 16) begin
                        // First 16 words are the chunk itself (big-endian)
                        W[schedule_index] <= {
                            message_block[schedule_index*4],
                            message_block[schedule_index*4 + 1],
                            message_block[schedule_index*4 + 2],
                            message_block[schedule_index*4 + 3]
                        };
                        schedule_index <= schedule_index + 1;
                    end else if (schedule_index < 64) begin
                        // Extend to 64 words
                        // Declare s0 and s1 as wires instead of using them directly
                        reg [31:0] w_s0, w_s1;
                        
                        // Calculate sigma0 and sigma1
                        sigma_0 s0_inst(.x(W[schedule_index-15]), .sigma0(w_s0));
                        sigma_1 s1_inst(.x(W[schedule_index-2]), .sigma1(w_s1));
                        
                        // Compute next word
                        W[schedule_index] <= w_s1 + W[schedule_index-7] + w_s0 + W[schedule_index-16];
                        schedule_index <= schedule_index + 1;
                    end
                    
                    if (schedule_index == 63) begin
                        // Initialize working variables
                        a <= h0; b <= h1; c <= h2; d <= h3;
                        e <= h4; f <= h5; g <= h6; h <= h7;
                        compression_index <= 0;
                    end
                end
                
                STATE_COMPRESS: begin
                    // Main compression loop
                    temp1 <= h + sig1_out + ch_out + K[compression_index] + W[compression_index];
                    temp2 <= sig0_out + maj_out;
                    
                    // Update working variables
                    h <= g;
                    g <= f;
                    f <= e;
                    e <= d + temp1;
                    d <= c;
                    c <= b;
                    b <= a;
                    a <= temp1 + temp2;
                    
                    compression_index <= compression_index + 1;
                end
                
                STATE_FINALIZE: begin
                    // Finalize the hash computation
                    h0 <= h0 + a;
                    h1 <= h1 + b;
                    h2 <= h2 + c;
                    h3 <= h3 + d;
                    h4 <= h4 + e;
                    h5 <= h5 + f;
                    h6 <= h6 + g;
                    h7 <= h7 + h;
                    
                    // Output the hash value
                    hash_value <= {h0 + a, h1 + b, h2 + c, h3 + d, h4 + e, h5 + f, h6 + g, h7 + h};
                    hash_valid <= 1;
                    
                    // Reset for next message
                    message_block_index <= 0;
                    schedule_index <= 0;
                    compression_index <= 0;
                    padding_done <= 0;
                end
            endcase
        end
    end

endmodule

// Top module for SHA-256 with string input
module sha256_top(
    input wire clk,
    input wire rst,
    input wire start,
    output wire done,
    output wire [255:0] hash
);

    // Test string: "Hello, SHA-256!" - Hard-coded for this implementation
    localparam STRING_LENGTH = 15;
    wire [8*STRING_LENGTH-1:0] test_string = "Hello, SHA-256!";
    
    reg [7:0] message_byte;
    reg message_valid;
    reg message_last;
    wire hash_valid;
    wire [255:0] hash_value;
    
    reg [7:0] byte_counter;
    reg process_started;
    
    // SHA-256 core instance
    sha256_core sha256_inst(
        .clk(clk),
        .rst(rst),
        .message_byte(message_byte),
        .message_valid(message_valid),
        .message_last(message_last),
        .hash_valid(hash_valid),
        .hash_value(hash_value)
    );
    
    // Control logic for feeding input string
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            byte_counter <= 0;
            message_valid <= 0;
            message_last <= 0;
            process_started <= 0;
        end else begin
            // Start processing when start signal is asserted
            if (start && !process_started) begin
                byte_counter <= 0;
                message_valid <= 1;
                process_started <= 1;
            end
            
            // Feed bytes to the SHA-256 core
            if (process_started && byte_counter < STRING_LENGTH) begin
                // Extract one byte at a time from the test string
                message_byte <= test_string[8*(STRING_LENGTH-1-byte_counter) +: 8];
                
                // Set last byte flag
                if (byte_counter == STRING_LENGTH - 1) begin
                    message_last <= 1;
                end
                
                byte_counter <= byte_counter + 1;
            end else if (byte_counter == STRING_LENGTH) begin
                // End of message
                message_valid <= 0;
                message_last <= 0;
                
                // Reset once hash is valid
                if (hash_valid) begin
                    process_started <= 0;
                    byte_counter <= 0;
                end
            end
        end
    end
    
    // Connect outputs
    assign done = hash_valid;
    assign hash = hash_value;

endmodule

// Testbench
module sha256_tb;
    reg clk;
    reg rst;
    reg start;
    wire done;
    wire [255:0] hash;
    
    // Instantiate the top module
    sha256_top sha256_inst(
        .clk(clk),
        .rst(rst),
        .start(start),
        .done(done),
        .hash(hash)
    );
    
    // Clock generation
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end
    
    // Test procedure
    initial begin
        // Initialize inputs
        rst = 1;
        start = 0;
        #20;
        
        // Release reset
        rst = 0;
        #10;
        
        // Start hash computation
        start = 1;
        #10;
        start = 0;
        
        // Wait for completion
        wait(done);
        
        // Display result
        $display("SHA-256 hash of 'Hello, SHA-256!':");
        $display("%x", hash);
        
        #100;
        $finish;
    end
    
    // Monitor hash output
    always @(posedge done) begin
        $display("Hash computation completed!");
    end
endmodule 
