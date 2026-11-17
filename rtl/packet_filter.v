module packet_filter #(

    parameter BLOCKED_IP = 32'hC0A80164,
    parameter BLOCKED_IP_2 = 32'h0A000032,
    parameter BLOCKED_DEST_IP = 32'hC0A801C8,

    parameter BLOCKED_PORT = 16'd23,
    parameter BLOCKED_PROTOCOL = 8'd17,

    parameter SYN_THRESHOLD = 4,
    parameter ICMP_THRESHOLD = 4

)(
    input wire clk,
    input wire reset,
    input wire packet_valid,

    input wire [31:0] source_ip,
    input wire [31:0] dest_ip,
    input wire [15:0] dest_port,
    input wire [7:0] protocol,
    input wire tcp_syn,

    output reg allow,
    output reg drop

    
);

    localparam TCP = 8'd6;
    localparam ICMP = 8'd1;
    reg [3:0] syn_count;
    reg [3:0] icmp_count;

    reg [3:0] window_count;

    // Sequential traffic monitoring
    always @(posedge clk or posedge reset) begin

        if (reset) begin

            syn_count <= 4'd0;
            icmp_count <= 4'd0;
            window_count <= 4'd0;

        end

        else if (packet_valid) begin

            if (window_count == 4'd7) begin

                window_count <= 4'd0;

                syn_count <= ((protocol == TCP) && tcp_syn)
                             ? 4'd1 : 4'd0;

                icmp_count <= (protocol == ICMP)
                              ? 4'd1 : 4'd0;

            end

            else begin

                window_count <= window_count + 1'b1;

                if ((protocol == TCP) && tcp_syn)
                    syn_count <= syn_count + 1'b1;

                if (protocol == ICMP)
                    icmp_count <= icmp_count + 1'b1;

            end

        end
    end


    // Combinational packet filtering
    always @(*) begin

        allow = 1'b0;
        drop = 1'b0;

        if (packet_valid) begin

            // Rule 1 and 2: Source IP blocking
            if ((source_ip == BLOCKED_IP) ||
                (source_ip == BLOCKED_IP_2))

                drop = 1'b1;


            // Rule 3: Destination IP blocking
            else if (dest_ip == BLOCKED_DEST_IP)

                drop = 1'b1;


            // Rule 4: Destination port filtering
            else if (dest_port == BLOCKED_PORT)

                drop = 1'b1;


            // Rule 5: Protocol filtering
            else if (protocol == BLOCKED_PROTOCOL)

                drop = 1'b1;


            // Rule 6: TCP SYN flood detection
            else if ((protocol == TCP) &&
         tcp_syn &&
         (syn_count >= SYN_THRESHOLD))

                drop = 1'b1;


            // Rule 7: ICMP traffic threshold detection
           else if ((protocol == ICMP) &&
         (icmp_count >= ICMP_THRESHOLD))

                drop = 1'b1;


            else

                allow = 1'b1;

        end
    end

endmodule