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


    integer pass_count = 0;
    integer fail_count = 0;

    // Instantiate packet filter
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
        .drop(drop)
    );

    // Clock generation
    always #5 clk = ~clk;


    // Reset task
    task reset_filter;
        begin
            @(negedge clk);
            packet_valid = 0;
            reset = 1;

            @(negedge clk);
            reset = 0;
        end
    endtask


    // Packet testing task
    task check_packet;

        input [31:0] src;
        input [31:0] dst;
        input [15:0] port;
        input [7:0] proto;
        input syn;
        input expected_drop;
        input [200:0] test_name;

        begin

            @(negedge clk);

            source_ip = src;
            dest_ip = dst;
            dest_port = port;
            protocol = proto;
            tcp_syn = syn;
            packet_valid = 1;

            // Wait for counter update
            @(posedge clk);
            #1;

            if ((drop === expected_drop) &&
                (allow === !expected_drop)) begin

                $display("PASS: %0s | ALLOW=%b DROP=%b",
                         test_name, allow, drop);

                pass_count = pass_count + 1;

            end

            else begin

                $display("FAIL: %0s | ALLOW=%b DROP=%b",
                         test_name, allow, drop);

                fail_count = fail_count + 1;

            end

            @(negedge clk);
            packet_valid = 0;

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

        #12;
        reset = 0;

        $display("\n==================================");
        $display(" HARDWARE PACKET FILTER TEST");
        $display("==================================\n");


        // TEST 1: Normal HTTP packet
        check_packet(
            32'hC0A80132,
            32'hC0A8010A,
            16'd80,
            8'd6,
            0,
            0,
            "Normal HTTP packet"
        );


        // TEST 2: First blocked source IP
        check_packet(
            32'hC0A80164,
            32'hC0A8010A,
            16'd80,
            8'd6,
            0,
            1,
            "Blocked source IP 1"
        );


        // TEST 3: Second blocked source IP
        check_packet(
            32'h0A000032,
            32'hC0A8010A,
            16'd80,
            8'd6,
            0,
            1,
            "Blocked source IP 2"
        );


        // TEST 4: Blocked destination IP
        check_packet(
            32'hC0A80132,
            32'hC0A801C8,
            16'd80,
            8'd6,
            0,
            1,
            "Blocked destination IP"
        );


        // TEST 5: Restricted destination port
        check_packet(
            32'hC0A80132,
            32'hC0A8010A,
            16'd23,
            8'd6,
            0,
            1,
            "Restricted port 23"
        );


        // TEST 6: Restricted UDP protocol
        check_packet(
            32'hC0A80132,
            32'hC0A8010A,
            16'd53,
            8'd17,
            0,
            1,
            "Restricted UDP protocol"
        );


        // TEST 7: Normal HTTPS packet
        check_packet(
            32'hC0A80120,
            32'hC0A8010A,
            16'd443,
            8'd6,
            0,
            0,
            "Normal HTTPS packet"
        );


        // TEST 8: Both IP and port restricted
        check_packet(
            32'hC0A80164,
            32'hC0A8010A,
            16'd23,
            8'd6,
            0,
            1,
            "Both IP and port restricted"
        );


        // TEST 9: TCP SYN threshold detection

        reset_filter();

        check_packet(
            32'hC0A80132, 32'hC0A8010A,
            16'd80, 8'd6, 1, 0,
            "SYN packet 1"
        );

        check_packet(
            32'hC0A80132, 32'hC0A8010A,
            16'd80, 8'd6, 1, 0,
            "SYN packet 2"
        );

        check_packet(
            32'hC0A80132, 32'hC0A8010A,
            16'd80, 8'd6, 1, 0,
            "SYN packet 3"
        );

        check_packet(
            32'hC0A80132, 32'hC0A8010A,
            16'd80, 8'd6, 1, 1,
            "SYN threshold exceeded"
        );


        // TEST 10: ICMP threshold detection

        reset_filter();

        check_packet(
            32'hC0A80132, 32'hC0A8010A,
            16'd0, 8'd1, 0, 0,
            "ICMP packet 1"
        );

        check_packet(
            32'hC0A80132, 32'hC0A8010A,
            16'd0, 8'd1, 0, 0,
            "ICMP packet 2"
        );

        check_packet(
            32'hC0A80132, 32'hC0A8010A,
            16'd0, 8'd1, 0, 0,
            "ICMP packet 3"
        );

        check_packet(
            32'hC0A80132, 32'hC0A8010A,
            16'd0, 8'd1, 0, 1,
            "ICMP threshold exceeded"
        );


        // Final summary

        $display("\n==================================");
        $display(" SIMULATION SUMMARY");
        $display("==================================");

        $display("Total Passed: %0d", pass_count);
        $display("Total Failed: %0d", fail_count);

        if (fail_count == 0)
            $display("RESULT: ALL TESTS PASSED");
        else
            $display("RESULT: SOME TESTS FAILED");

        $display("==================================\n");

        $finish;

    end


    // Generate waveform
    initial begin

        $dumpfile("simulation/packet_filter.vcd");
        $dumpvars(0, packet_filter_tb);

    end

endmodule