`timescale 1ns/1ps

module packet_filter_tb;

    reg clk;
    reg reset;
    reg packet_valid;

    reg [31:0] source_ip;
    reg [31:0] dest_ip;
    reg [15:0] dest_port;
    reg [7:0] protocol;
    reg tcp_syn;

    wire allow;
    wire drop;

    wire [3:0] syn_count;
    wire [3:0] icmp_count;

    packet_filter uut (
        .clk(clk),
        .reset(reset),
        .packet_valid(packet_valid),
        .source_ip(source_ip),
        .dest_ip(dest_ip),
        .dest_port(dest_port),
        .protocol(protocol),
        .tcp_syn(tcp_syn),
        .allow(allow),
        .drop(drop),
        .syn_count(syn_count),
        .icmp_count(icmp_count)
    );

    always #5 clk = ~clk;

    task send_packet;
        input [31:0] src_ip;
        input [31:0] dst_ip;
        input [15:0] port;
        input [7:0] proto;
        input syn;

        begin
            source_ip = src_ip;
            dest_ip = dst_ip;
            dest_port = port;
            protocol = proto;
            tcp_syn = syn;
            packet_valid = 1'b1;

            #10;

            $display("Source IP: %h | Port: %d | Protocol: %d | SYN: %b | ALLOW: %b | DROP: %b",
                     source_ip, dest_port, protocol, tcp_syn, allow, drop);

            packet_valid = 1'b0;
            #10;
        end
    endtask

    initial begin

        clk = 0;
        reset = 1;
        packet_valid = 0;

        source_ip = 0;
        dest_ip = 0;
        dest_port = 0;
        protocol = 0;
        tcp_syn = 0;

        #10;
        reset = 0;

        $display("----- PACKET FILTER TEST -----");

        $display("TEST 1: Normal HTTP packet");
        send_packet(
            32'hC0A80132,
            32'hC0A8010A,
            16'd80,
            8'd6,
            1'b0
        );

        $display("TEST 2: Blocked port");
        send_packet(
            32'hC0A80132,
            32'hC0A8010A,
            16'd23,
            8'd6,
            1'b0
        );

        $display("TEST 3: Blocked source IP");
        send_packet(
            32'hC0A80164,
            32'hC0A8010A,
            16'd80,
            8'd6,
            1'b0
        );

        $display("TEST 4: Normal HTTPS packet");
        send_packet(
            32'hC0A80120,
            32'hC0A8010A,
            16'd443,
            8'd6,
            1'b0
        );

        $display("TEST 5: SYN traffic");

        send_packet(32'hC0A80132, 32'hC0A8010A, 16'd80, 8'd6, 1'b1);
        send_packet(32'hC0A80132, 32'hC0A8010A, 16'd80, 8'd6, 1'b1);
        send_packet(32'hC0A80132, 32'hC0A8010A, 16'd80, 8'd6, 1'b1);
        send_packet(32'hC0A80132, 32'hC0A8010A, 16'd80, 8'd6, 1'b1);

        $display("TEST 6: ICMP traffic");

        send_packet(32'hC0A80132, 32'hC0A8010A, 16'd0, 8'd1, 1'b0);
        send_packet(32'hC0A80132, 32'hC0A8010A, 16'd0, 8'd1, 1'b0);
        send_packet(32'hC0A80132, 32'hC0A8010A, 16'd0, 8'd1, 1'b0);
        send_packet(32'hC0A80132, 32'hC0A8010A, 16'd0, 8'd1, 1'b0);

        $display("----- TEST COMPLETE -----");

        $finish;
    end

    initial begin
        $dumpfile("simulation/packet_filter.vcd");
        $dumpvars(0, packet_filter_tb);
    end

endmodule