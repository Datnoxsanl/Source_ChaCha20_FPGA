#include <stdio.h>
#include <string.h>
#include "xparameters.h"
#include "xil_io.h"
#include "xil_printf.h"
#include "myip_ChaCha_pipeline.h"


#define BASE_ADDR      XPAR_MYIP_CHACHA_PIPELINE_0_S00_AXI_BASEADDR

#define REG_CTRL          (MYIP_CHACHA_PIPELINE_S00_AXI_SLV_REG0_OFFSET)
#define REG_STATUS        (MYIP_CHACHA_PIPELINE_S00_AXI_SLV_REG1_OFFSET)
#define REG_COUNTER       (MYIP_CHACHA_PIPELINE_S00_AXI_SLV_REG2_OFFSET)
#define REG_NONCE_BASE    (MYIP_CHACHA_PIPELINE_S00_AXI_SLV_REG3_OFFSET)
#define REG_KEY_BASE      (MYIP_CHACHA_PIPELINE_S00_AXI_SLV_REG6_OFFSET)
#define REG_PLAIN_BASE    (MYIP_CHACHA_PIPELINE_S00_AXI_SLV_REG14_OFFSET)
#define REG_CIPHER_BASE   (MYIP_CHACHA_PIPELINE_S00_AXI_SLV_REG30_OFFSET)


void write_key(u32* key_arr) {
    for (int i = 0; i < 8; i++) {
        MYIP_CHACHA_PIPELINE_mWriteReg(BASE_ADDR, REG_KEY_BASE + (i * 4), key_arr[i]);
    }
}

void write_nonce(u32* nonce_arr) {
    for (int i = 0; i < 3; i++) {
        MYIP_CHACHA_PIPELINE_mWriteReg(BASE_ADDR, REG_NONCE_BASE + (i * 4), nonce_arr[i]);
    }
}


void string_to_u32_array(char* str, u32* out_arr) {
    memset(out_arr, 0, 16 * sizeof(u32));
    int len = strlen(str);
    if (len > 64) len = 64;

    for (int i = 0; i < len; i++) {
        int word_idx = i / 4;
        int byte_idx = i % 4;
        out_arr[word_idx] |= ((u32)str[i] & 0xFF) << (byte_idx * 8);
    }
}


int main() {

    u32 key[8] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
    };
    u32 nonce[3] = {0x00000000, 0x4a000000, 0x00000000};
    u32 counter = 1;

    char input_buffer[65];
    u32 plaintext_words[16];
    u32 ciphertext_words[16];

    xil_printf("   FPGA CHACHA20 Pipeline Quarter Round\r\n");
    xil_printf("   Base Address: 0x%x\r\n", BASE_ADDR);

    write_key(key);
    write_nonce(nonce);
    MYIP_CHACHA_PIPELINE_mWriteReg(BASE_ADDR, REG_COUNTER, counter);
    xil_printf("[Init] Key & Nonce loaded.\r\n");
    while(1) {
        xil_printf("\r\n> Nhap Plaintext: ");
        int idx = 0;
        while(1) {
            char c = inbyte();
            outbyte(c);

            if(c == '\r' || c == '\n') {
                input_buffer[idx] = '\0';
                break;
            }
            if(idx < 64) {
                input_buffer[idx] = c;
                idx++;
            }
        }
        xil_printf("\r\n");

        if (idx == 0) continue;

        string_to_u32_array(input_buffer, plaintext_words);

        for (int i = 0; i < 16; i++) {
            MYIP_CHACHA_PIPELINE_mWriteReg(BASE_ADDR, REG_PLAIN_BASE + (i*4), plaintext_words[i]);
        }


        MYIP_CHACHA_PIPELINE_mWriteReg(BASE_ADDR, REG_CTRL, 0x00);

        MYIP_CHACHA_PIPELINE_mWriteReg(BASE_ADDR, REG_CTRL, 0x01);
        MYIP_CHACHA_PIPELINE_mWriteReg(BASE_ADDR, REG_CTRL, 0x00);

        volatile u32 status_val;
        int timeout_ctr = 1000000;

        do {
            status_val = MYIP_CHACHA_PIPELINE_mReadReg(BASE_ADDR, REG_STATUS);
            timeout_ctr--;
        } while ( (status_val & 0x01) == 0 && timeout_ctr > 0 );

        if (timeout_ctr <= 0) {
            xil_printf("[ERROR] Hardware Timeout! Status Reg = 0x%x\r\n", status_val);
            continue;
        }

        xil_printf("Caculator finished. Reading result...\r\n");
        for (int i = 0; i < 16; i++) {
            ciphertext_words[i] = MYIP_CHACHA_PIPELINE_mReadReg(BASE_ADDR, REG_CIPHER_BASE + (i*4));
        }

        xil_printf("Ciphertext:\r\n");
        for(int i=0; i<16; i++) {
            xil_printf("%08x ", ciphertext_words[i]);
            if ((i+1) % 4 == 0) xil_printf("\r\n");
        }
        xil_printf("------------------------------------------\r\n");
    }

    return 0;
}
