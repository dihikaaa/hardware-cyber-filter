module packet_filter #(
    parameter BLOCKED_IP = 32'hC0A80164,
    parameter BLOCKED_PORT = 16'd23,
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
    output reg drop,

    output reg [3:0] syn_count,
    output reg [3:0] icmp_count
);

    parameter TCP = 8'd6;
    parameter ICMP = 8'd1;

    reg [3:0] window_count;

    always @(posedge clk or posedge reset) begin
        if (reset) begin
            syn_count <= 4'd0;
            icmp_count <= 4'd0;
            window_count <= 4'd0;
        end
        else if (packet_valid) begin

            if ((protocol == TCP) && tcp_syn)
                syn_count <= syn_count + 1'b1;

            if (protocol == ICMP)
                icmp_count <= icmp_count + 1'b1;

            if (window_count == 4'd7) begin
                window_count <= 4'd0;
                syn_count <= 4'd0;
                icmp_count <= 4'd0;
            end
            else begin
                window_count <= window_count + 1'b1;
            end
        end
    end

    always @(*) begin
        allow = 1'b0;
        drop = 1'b0;

        if (packet_valid) begin

            if (source_ip == BLOCKED_IP)
                drop = 1'b1;

            else if (dest_port == BLOCKED_PORT)
                drop = 1'b1;

            else if ((protocol == TCP) &&
                     tcp_syn &&
                     (syn_count >= SYN_THRESHOLD - 1))
                drop = 1'b1;

            else if ((protocol == ICMP) &&
                     (icmp_count >= ICMP_THRESHOLD - 1))
                drop = 1'b1;

            else
                allow = 1'b1;
        end
    end

endmodule