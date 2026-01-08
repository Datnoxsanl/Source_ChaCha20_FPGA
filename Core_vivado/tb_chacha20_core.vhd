library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity tb_chacha20_core is
end entity tb_chacha20_core;

architecture sim of tb_chacha20_core is
    -- Signals k?t n?i v?i UUT
    signal clk            : std_logic := '0';
    signal reset_n        : std_logic := '0';
    signal init           : std_logic := '0';
    signal load_next      : std_logic := '0';
    signal key            : std_logic_vector(255 downto 0) := (others => '0');
    signal nonce_96       : std_logic_vector(95 downto 0)  := (others => '0');
    signal counter_32     : std_logic_vector(31 downto 0)  := (others => '0');
    signal rounds         : std_logic_vector(4 downto 0)   := "10100"; -- 20 Rounds
    signal data_in        : std_logic_vector(511 downto 0) := (others => '0');
    signal ready          : std_logic;
    signal data_out       : std_logic_vector(511 downto 0);
    signal data_out_valid : std_logic;
    signal monitor_keystream : std_logic_vector(511 downto 0) := (others => '0');
    constant CLK_PERIOD : time := 10 ns;

begin
    -- Kh?i t?o Module ChaCha Core
    uut: entity work.chacha20_core
        port map (
            clk            => clk,
            reset_n        => reset_n,
            init           => init,
            load_next      => load_next,
            key            => key,
            keylen         => '1',
            nonce_96       => nonce_96,
            counter_32     => counter_32,
            rounds         => rounds,
            data_in        => data_in,
            ready          => ready,
            data_out       => data_out,
            data_out_valid => data_out_valid
        );

    -- Clock Generation
    clk_process : process
    begin
        clk <= '0'; wait for CLK_PERIOD/2;
        clk <= '1'; wait for CLK_PERIOD/2;
    end process;

    -- Stimulus Process
    process
    begin		
        -- 1. Reset h? th?ng
        reset_n <= '0';
        init    <= '0';
        wait for 100 ns; 
        reset_n <= '1';
        wait until rising_edge(clk);
        wait for CLK_PERIOD; 

        -- 2. GIAI ?O?N 1: TÌM KEYSTREAM (Vector RFC 7539)
        -- Data_in = 0 giúp data_out hi?n th? tr?c ti?p Keystream
        key        <= x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        nonce_96   <= x"000000000000000000000002";
        counter_32 <= x"00000001";
        data_in    <= (others => '0'); 
        
        -- Kích xung init (Quan tr?ng: dùng falling_edge ?? tránh l?i timing)
        wait until falling_edge(clk);
        init <= '1';
        wait until falling_edge(clk);
        init <= '0';

        -- Ch? x? lý hoàn t?t
        wait until data_out_valid = '1';
        monitor_keystream <= data_out;
        wait for 100 ns;

        -- 3. GIAI ?O?N 2: MÃ HÓA PLAINTEXT TH?C T?
        -- Ch? module s?n sàng cho block ti?p theo
        wait until ready = '1';
        
        -- N?p Plaintext khác 0
        data_in <= x"5468697320697320612074657374206d65737361676520666f72204368614368" & 
                   x"61323020506970656c696e65642048617264776172652044657369676e212121";
        
        wait until falling_edge(clk);
        init <= '1';
        wait until falling_edge(clk);
        init <= '0';

        wait until data_out_valid = '1';
        
        -- K?t thúc mô ph?ng
        wait for 500 ns;
        report "Simulation Success: Keystream and Ciphertext captured.";
        std.env.finish; -- D?ng mô ph?ng (Vivado/GHDL)
    end process;

end architecture sim;