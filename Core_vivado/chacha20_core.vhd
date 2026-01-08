library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity chacha20_core is
    port (
        clk            : in  std_logic;
        reset_n        : in  std_logic; 

        init           : in  std_logic;
        load_next      : in  std_logic;

        key            : in  std_logic_vector(255 downto 0);
        keylen         : in  std_logic;
        nonce_96       : in  std_logic_vector(95 downto 0);
        counter_32     : in  std_logic_vector(31 downto 0);
        rounds         : in  std_logic_vector(4 downto 0);

        data_in        : in  std_logic_vector(511 downto 0);

        ready          : out std_logic;
        data_out       : out std_logic_vector(511 downto 0);
        data_out_valid : out std_logic
    );
end entity chacha20_core;

architecture rtl of chacha20_core is

    -- Constants (RFC 78439)
    constant SIGMA0 : unsigned(31 downto 0) := x"61707865"; -- "apxe"
    constant SIGMA1 : unsigned(31 downto 0) := x"3320646e"; -- "3 dn"
    constant SIGMA2 : unsigned(31 downto 0) := x"79622d32"; -- "yb-2"
    constant SIGMA3 : unsigned(31 downto 0) := x"6b206574"; -- "k et"

    -- FSM States 
    constant CTRL_IDLE     : unsigned(2 downto 0) := "000";
    constant CTRL_INIT     : unsigned(2 downto 0) := "001";
    constant CTRL_ROUNDS   : unsigned(2 downto 0) := "010";
    constant CTRL_FINALIZE : unsigned(2 downto 0) := "011";
    constant CTRL_DONE     : unsigned(2 downto 0) := "100";
    constant CTRL_WAIT_PIPE: unsigned(2 downto 0) := "101"; -- Tr?ng thái ch? pipeline

    -- Datapath types
    type state_array is array (0 to 15) of unsigned(31 downto 0);

    -- Registers (including update variables and write enable)
    signal state_reg, state_new : state_array;
    signal state_we             : std_logic;

    signal data_out_reg, data_out_new : std_logic_vector(511 downto 0);
    signal update_output              : std_logic;

    signal data_out_valid_reg, data_out_valid_new, data_out_valid_we : std_logic;

    signal qr_ctr_reg, qr_ctr_new, qr_ctr_we, qr_ctr_inc, qr_ctr_rst : std_logic;
    signal dr_ctr_reg, dr_ctr_new : unsigned(3 downto 0);
    signal dr_ctr_we, dr_ctr_inc, dr_ctr_rst : std_logic;

    signal block_ctr_reg, block_ctr_new : unsigned(31 downto 0);
    signal block_ctr_we, block_ctr_inc, block_ctr_set : std_logic;

    signal ready_reg, ready_new, ready_we : std_logic;

    signal chacha_ctrl_reg, chacha_ctrl_new : unsigned(2 downto 0);
    signal chacha_ctrl_we : std_logic;

    -- Wires / Intermediate signals
    signal init_state_word : state_array;
    signal init_state, update_state : std_logic;
    signal pipe_rst : std_logic;
    signal pipe_wait_ctr : unsigned(2 downto 0);

    -- Pipeline Interface
    type pipe_io_array is array (0 to 3) of std_logic_vector(31 downto 0);
    signal qr_in_a, qr_in_b, qr_in_c, qr_in_d : pipe_io_array;
    signal qr_out_a, qr_out_b, qr_out_c, qr_out_d : pipe_io_array;

    -- Function l2b
    function l2b(op : unsigned(31 downto 0)) return unsigned is
    begin
        return op(7 downto 0) & op(15 downto 8) & op(23 downto 16) & op(31 downto 24);
    end function;

begin

    pipe_rst <= not reset_n;

    -- Instantiation of 4 Parallel Pipelined QR Modules
    qr_gen: for i in 0 to 3 generate
        qr_unit: entity work.chacha_qr_pipelined
            port map (
                clk    => clk,
                rst    => pipe_rst,
                a_in   => qr_in_a(i), 
                b_in   => qr_in_b(i),
                c_in   => qr_in_c(i),
                d_in   => qr_in_d(i),
                a_out  => qr_out_a(i),
                b_out  => qr_out_b(i),
                c_out  => qr_out_c(i),
                d_out  => qr_out_d(i)
            );
    end generate;

    ----------------------------------------------------------------
    -- reg_update
    -- Kh?p 1:1 logic v?i kh?i 'reg_update' trong Verilog.
    ----------------------------------------------------------------
    process(clk)
    begin
        if rising_edge(clk) then
            if reset_n = '0' then
                state_reg <= (others => (others => '0'));
                data_out_reg <= (others => '0');
                data_out_valid_reg <= '0';
                qr_ctr_reg <= '0';
                dr_ctr_reg <= (others => '0');
                block_ctr_reg <= (others => '0');
                chacha_ctrl_reg <= CTRL_IDLE;
                ready_reg <= '1';
                pipe_wait_ctr <= (others => '0');
            else
                if state_we = '1' then state_reg <= state_new; end if;
                if update_output = '1' then data_out_reg <= data_out_new; end if;
                if data_out_valid_we = '1' then data_out_valid_reg <= data_out_valid_new; end if;
                if qr_ctr_we = '1' then qr_ctr_reg <= qr_ctr_new; end if;
                if dr_ctr_we = '1' then dr_ctr_reg <= dr_ctr_new; end if;
                if block_ctr_we = '1' then block_ctr_reg <= block_ctr_new; end if;
                if ready_we = '1' then ready_reg <= ready_new; end if;
                if chacha_ctrl_we = '1' then chacha_ctrl_reg <= chacha_ctrl_new; end if;

                -- Qu?n lý b? ??m ch? Pipeline
                if chacha_ctrl_reg = CTRL_WAIT_PIPE then
                    pipe_wait_ctr <= pipe_wait_ctr + 1;
                else
                    pipe_wait_ctr <= (others => '0');
                end if;
            end if;
        end if;
    end process;

    ----------------------------------------------------------------
    -- init_state_logic
    -- Tính toán tr?ng thái ban ??u d?a trên Key, Nonce, Counter.
    ----------------------------------------------------------------
    process(key, nonce_96, block_ctr_reg)
        variable key_words : state_array;
    begin
        for i in 0 to 7 loop
            key_words(i) := l2b(unsigned(key(255-i*32 downto 224-i*32)));
        end loop;

        init_state_word(0) <= SIGMA0; 
        init_state_word(1) <= SIGMA1;
        init_state_word(2) <= SIGMA2; 
        init_state_word(3) <= SIGMA3;
        init_state_word(4 to 11) <= key_words(0 to 7);
        init_state_word(12) <= block_ctr_reg;
        init_state_word(13) <= l2b(unsigned(nonce_96(95 downto 64)));
        init_state_word(14) <= l2b(unsigned(nonce_96(63 downto 32)));
        init_state_word(15) <= l2b(unsigned(nonce_96(31 downto 0)));
    end process;

    ----------------------------------------------------------------
    -- state_logic & Pipeline Routing
    ----------------------------------------------------------------
    process(init_state, init_state_word, update_state, qr_ctr_reg, state_reg, qr_out_a, qr_out_b, qr_out_c, qr_out_d, pipe_wait_ctr)
    begin
        state_new <= state_reg;
        state_we <= '0';
        qr_in_a <= (others => (others => '0')); qr_in_b <= (others => (others => '0'));
        qr_in_c <= (others => (others => '0')); qr_in_d <= (others => (others => '0'));

        if init_state = '1' then
            state_new <= init_state_word;
            state_we <= '1';
        end if;

        if update_state = '1' then
            -- ??a d? li?u vào Pipeline (ROUNDS)
            if qr_ctr_reg = '0' then -- Column Round
                for i in 0 to 3 loop
                    qr_in_a(i) <= std_logic_vector(state_reg(i));
                    qr_in_b(i) <= std_logic_vector(state_reg(i+4));
                    qr_in_c(i) <= std_logic_vector(state_reg(i+8));
                    qr_in_d(i) <= std_logic_vector(state_reg(i+12));
                end loop;
            else -- Diagonal Round
                qr_in_a(0)<=std_logic_vector(state_reg(0)); qr_in_b(0)<=std_logic_vector(state_reg(5));
                qr_in_c(0)<=std_logic_vector(state_reg(10));qr_in_d(0)<=std_logic_vector(state_reg(15));
                qr_in_a(1)<=std_logic_vector(state_reg(1)); qr_in_b(1)<=std_logic_vector(state_reg(6));
                qr_in_c(1)<=std_logic_vector(state_reg(11));qr_in_d(1)<=std_logic_vector(state_reg(12));
                qr_in_a(2)<=std_logic_vector(state_reg(2)); qr_in_b(2)<=std_logic_vector(state_reg(7));
                qr_in_c(2)<=std_logic_vector(state_reg(8)); qr_in_d(2)<=std_logic_vector(state_reg(13));
                qr_in_a(3)<=std_logic_vector(state_reg(3)); qr_in_b(3)<=std_logic_vector(state_reg(4));
                qr_in_c(3)<=std_logic_vector(state_reg(9)); qr_in_d(3)<=std_logic_vector(state_reg(14));
            end if;
        end if;

        -- Khi Pipeline hoàn thành (Sau 4 chu k?)
        if pipe_wait_ctr = 3 then
            state_we <= '1';
            if qr_ctr_reg = '0' then
                for i in 0 to 3 loop
                    state_new(i)<=unsigned(qr_out_a(i)); state_new(i+4)<=unsigned(qr_out_b(i));
                    state_new(i+8)<=unsigned(qr_out_c(i)); state_new(i+12)<=unsigned(qr_out_d(i));
                end loop;
            else
                state_new(0)<=unsigned(qr_out_a(0)); state_new(5)<=unsigned(qr_out_b(0));
                state_new(10)<=unsigned(qr_out_c(0)); state_new(15)<=unsigned(qr_out_d(0));
                state_new(1)<=unsigned(qr_out_a(1)); state_new(6)<=unsigned(qr_out_b(1));
                state_new(11)<=unsigned(qr_out_c(1)); state_new(12)<=unsigned(qr_out_d(1));
                state_new(2)<=unsigned(qr_out_a(2)); state_new(7)<=unsigned(qr_out_b(2));
                state_new(8)<=unsigned(qr_out_c(2)); state_new(13)<=unsigned(qr_out_d(2));
                state_new(3)<=unsigned(qr_out_a(3)); state_new(4)<=unsigned(qr_out_b(3));
                state_new(9)<=unsigned(qr_out_c(3)); state_new(14)<=unsigned(qr_out_d(3));
            end if;
        end if;
    end process;

    ----------------------------------------------------------------
    -- data_out_logic
    ----------------------------------------------------------------
process(init_state_word, state_reg, data_in)
        variable block_state : std_logic_vector(511 downto 0);
        variable word_sum : unsigned(31 downto 0);
    begin
        for i in 0 to 15 loop
            word_sum := init_state_word(i) + state_reg(i);
            -- Gán chính xác v? trí c?a t?ng Word trong chu?i 512-bit
            block_state(511 - (i*32) downto 512 - ((i+1)*32)) := std_logic_vector(l2b(word_sum));
        end loop;
        data_out_new <= data_in xor block_state;
    end process;

    ----------------------------------------------------------------
    -- Counters & Control FSM (Kh?p 1:1 logic Verilog)
    ----------------------------------------------------------------
    qr_ctr_logic: process(qr_ctr_rst, qr_ctr_inc, qr_ctr_reg)
    begin
        qr_ctr_new <= '0'; qr_ctr_we <= '0';
        if qr_ctr_rst = '1' then qr_ctr_new <= '0'; qr_ctr_we <= '1';
        elsif qr_ctr_inc = '1' then qr_ctr_new <= not qr_ctr_reg; qr_ctr_we <= '1'; end if;
    end process;

    dr_ctr_logic: process(dr_ctr_rst, dr_ctr_inc, dr_ctr_reg)
    begin
        dr_ctr_new <= (others => '0'); dr_ctr_we <= '0';
        if dr_ctr_rst = '1' then dr_ctr_new <= (others => '0'); dr_ctr_we <= '1';
        elsif dr_ctr_inc = '1' then dr_ctr_new <= dr_ctr_reg + 1; dr_ctr_we <= '1'; end if;
    end process;

    block_ctr_logic: process(block_ctr_set, block_ctr_inc, block_ctr_reg, counter_32)
    begin
        block_ctr_new <= (others => '0'); block_ctr_we <= '0';
        if block_ctr_set = '1' then block_ctr_new <= unsigned(counter_32); block_ctr_we <= '1';
        elsif block_ctr_inc = '1' then block_ctr_new <= block_ctr_reg + 1; block_ctr_we <= '1'; end if;
    end process;

    chacha_ctrl_fsm: process(chacha_ctrl_reg, init, load_next, qr_ctr_reg, dr_ctr_reg, rounds, pipe_wait_ctr)
    begin
        -- Defaults
        init_state <= '0'; update_state <= '0'; update_output <= '0';
        qr_ctr_inc <= '0'; qr_ctr_rst <= '0'; dr_ctr_inc <= '0'; dr_ctr_rst <= '0';
        block_ctr_inc <= '0'; block_ctr_set <= '0'; ready_new <= '0'; ready_we <= '0';
        data_out_valid_new <= '0'; data_out_valid_we <= '1';
        chacha_ctrl_new <= chacha_ctrl_reg; chacha_ctrl_we <= '0';

        case chacha_ctrl_reg is
            when CTRL_IDLE =>
                if init = '1' then
                    block_ctr_set <= '1'; ready_new <= '0'; ready_we <= '1';
                    chacha_ctrl_new <= CTRL_INIT; chacha_ctrl_we <= '1';
                end if;

            when CTRL_INIT =>
                init_state <= '1'; qr_ctr_rst <= '1'; dr_ctr_rst <= '1';
                chacha_ctrl_new <= CTRL_ROUNDS; chacha_ctrl_we <= '1';

            when CTRL_ROUNDS =>
                update_state <= '1';
                chacha_ctrl_new <= CTRL_WAIT_PIPE; chacha_ctrl_we <= '1';

            when CTRL_WAIT_PIPE =>
                if pipe_wait_ctr = 3 then
                    qr_ctr_inc <= '1';
                    if qr_ctr_reg = '1' then
                        dr_ctr_inc <= '1';
                        if dr_ctr_reg = unsigned(rounds(4 downto 1)) then
                            chacha_ctrl_new <= CTRL_FINALIZE;
                        else
                            chacha_ctrl_new <= CTRL_ROUNDS;
                        end if;
                    else
                        chacha_ctrl_new <= CTRL_ROUNDS;
                    end if;
                    chacha_ctrl_we <= '1';
                end if;

            when CTRL_FINALIZE =>
                ready_new <= '1'; ready_we <= '1'; update_output <= '1';
                data_out_valid_new <= '1'; chacha_ctrl_new <= CTRL_DONE; chacha_ctrl_we <= '1';

            when CTRL_DONE =>
                if init = '1' then
                    ready_new <= '0'; ready_we <= '1'; data_out_valid_new <= '0';
                    block_ctr_set <= '1'; chacha_ctrl_new <= CTRL_INIT; chacha_ctrl_we <= '1';
                elsif load_next = '1' then
                    ready_new <= '0'; ready_we <= '1'; data_out_valid_new <= '0';
                    block_ctr_inc <= '1'; chacha_ctrl_new <= CTRL_INIT; chacha_ctrl_we <= '1';
                end if;

            when others => chacha_ctrl_new <= CTRL_IDLE; chacha_ctrl_we <= '1';
        end case;
    end process;

    ready <= ready_reg;
    data_out_valid <= data_out_valid_reg;
    data_out <= data_out_reg;

end architecture rtl;