library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity chacha_qr_pipelined is
    port (
        clk    : in  std_logic;
        rst    : in  std_logic;
        a_in   : in  std_logic_vector(31 downto 0);
        b_in   : in  std_logic_vector(31 downto 0);
        c_in   : in  std_logic_vector(31 downto 0);
        d_in   : in  std_logic_vector(31 downto 0);
        
        a_out  : out std_logic_vector(31 downto 0);
        b_out  : out std_logic_vector(31 downto 0);
        c_out  : out std_logic_vector(31 downto 0);
        d_out  : out std_logic_vector(31 downto 0)
    );
end entity chacha_qr_pipelined;

architecture rtl of chacha_qr_pipelined is
    -- Stage 1 Registers
    signal a1, b1, c1, d1 : unsigned(31 downto 0);
    -- Stage 2 Registers
    signal a2, b2, c2, d2 : unsigned(31 downto 0);
    -- Stage 3 Registers
    signal a3, b3, c3, d3 : unsigned(31 downto 0);
    -- Stage 4 Registers
    signal a4, b4, c4, d4 : unsigned(31 downto 0);
begin

    -------------------------------------------------------
    -- STAGE 1: a = a + b, d = (d ^ a) <<< 16
    -------------------------------------------------------
    proc_stage1: process(clk)
        variable v_a : unsigned(31 downto 0);
        variable v_d : unsigned(31 downto 0);
    begin
        if rising_edge(clk) then
            if rst = '1' then
                a1 <= (others => '0'); b1 <= (others => '0');
                c1 <= (others => '0'); d1 <= (others => '0');
            else
                v_a := unsigned(a_in) + unsigned(b_in);
                v_d := unsigned(d_in) xor v_a;
                
                a1 <= v_a;
                b1 <= unsigned(b_in);
                c1 <= unsigned(c_in);
                d1 <= v_d(15 downto 0) & v_d(31 downto 16); -- Rotate 16
            end if;
        end if;
    end process;

    -------------------------------------------------------
    -- STAGE 2: c = c + d, b = (b ^ c) <<< 12
    -------------------------------------------------------
    proc_stage2: process(clk)
        variable v_c : unsigned(31 downto 0);
        variable v_b : unsigned(31 downto 0);
    begin
        if rising_edge(clk) then
            if rst = '1' then
                a2 <= (others => '0'); b2 <= (others => '0');
                c2 <= (others => '0'); d2 <= (others => '0');
            else
                v_c := c1 + d1;
                v_b := b1 xor v_c;
                
                a2 <= a1;
                b2 <= v_b(19 downto 0) & v_b(31 downto 20); -- Rotate 12
                c2 <= v_c;
                d2 <= d1;
            end if;
        end if;
    end process;

    -------------------------------------------------------
    -- STAGE 3: a = a + b, d = (d ^ a) <<< 8
    -------------------------------------------------------
    proc_stage3: process(clk)
        variable v_a : unsigned(31 downto 0);
        variable v_d : unsigned(31 downto 0);
    begin
        if rising_edge(clk) then
            if rst = '1' then
                a3 <= (others => '0'); b3 <= (others => '0');
                c3 <= (others => '0'); d3 <= (others => '0');
            else
                v_a := a2 + b2;
                v_d := d2 xor v_a;
                
                a3 <= v_a;
                b3 <= b2;
                c3 <= c2;
                d3 <= v_d(23 downto 0) & v_d(31 downto 24); -- Rotate 8
            end if;
        end if;
    end process;

    -------------------------------------------------------
    -- STAGE 4: c = c + d, b = (b ^ c) <<< 7
    -------------------------------------------------------
    proc_stage4: process(clk)
        variable v_c : unsigned(31 downto 0);
        variable v_b : unsigned(31 downto 0);
    begin
        if rising_edge(clk) then
            if rst = '1' then
                a4 <= (others => '0'); b4 <= (others => '0');
                c4 <= (others => '0'); d4 <= (others => '0');
            else
                v_c := c3 + d3;
                v_b := b3 xor v_c;
                
                a4 <= a3;
                b4 <= v_b(24 downto 0) & v_b(31 downto 25); -- Rotate 7
                c4 <= v_c;
                d4 <= d3;
            end if;
        end if;
    end process;

    -- Output Assignment
    a_out <= std_logic_vector(a4);
    b_out <= std_logic_vector(b4);
    c_out <= std_logic_vector(c4);
    d_out <= std_logic_vector(d4);

end architecture rtl;
