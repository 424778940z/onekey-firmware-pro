/* Trezor v2 bootloader linker script */

ENTRY(reset_handler)

MEMORY {
  FLASH  (rx)  : ORIGIN = 0x08020000, LENGTH = 256K
  SRAM   (wal) : ORIGIN = 0x20000000, LENGTH = 128K
  AXIRAM (wal) : ORIGIN = 0x24000000, LENGTH = 512K
  /* SRAM3 is used for DMA */
  SRAM3  (wal) : ORIGIN = 0x30040000, LENGTH = 32K
}

main_stack_base = ORIGIN(SRAM) + LENGTH(SRAM); /* 8-byte aligned full descending stack */

/* used by the startup code to populate variables used by the C code */
data_lma = LOADADDR(.data);
data_vma = ADDR(.data);
data_size = SIZEOF(.data);

/* used by the startup code to wipe memory */
axiram_start = ORIGIN(AXIRAM);
axiram_end = ORIGIN(AXIRAM) + LENGTH(AXIRAM);

/* used by the startup code to wipe memory */
sram_start = ORIGIN(SRAM);
sram_end = ORIGIN(SRAM) + LENGTH(SRAM);

_codelen = SIZEOF(.flash) + SIZEOF(.data) + SIZEOF(.padding);

SECTIONS {
  .header : ALIGN(4) {
    KEEP(*(.header));
  } >FLASH AT>FLASH

  .flash : ALIGN(512) {
    KEEP(*(.vector_table));
    . = ALIGN(4);
    *(.text*);
    . = ALIGN(4);
    *(.rodata*);
    . = ALIGN(4);
    *(.ARM.exidx*);
    . = ALIGN(512);
  } >FLASH AT>FLASH

  .data : ALIGN(4) {
    *(.data*);
    . = ALIGN(512);
  } >SRAM AT>FLASH

  .padding : {
    KEEP(*(.padding));
    FILL(0xDEADBEEF); /* fill pattern */
    . = LENGTH(FLASH) - SIZEOF(.header) - SIZEOF(.flash) - SIZEOF(.data) - 1 - 8;
    BYTE(0x00); /* needed to keep this section without references in .s or .c */
  } >FLASH AT>FLASH

  .bss : ALIGN(4) {
    *(.bss*);
    . = ALIGN(4);
  } >SRAM

  .stack : ALIGN(8) {
    . = 4K; /* this acts as a build time assertion that at least this much memory is available for stack use */
  } >SRAM

  .sram3 : ALIGN(4) {
    *(.sram3*);
    . = ALIGN(4);
  } >SRAM3

  /* this is needed, otherwise will have "undefined reference to `end'" error */
  .heap : ALIGN(4) {
    PROVIDE ( end = . );
    PROVIDE ( _end = . );
    . = 512K; /* this acts as a build time assertion that at least this much memory is available for heap use */
    /*. = ABSOLUTE(sram_end - 16K);  this explicitly sets the end of the heap effectively giving the stack at most 16K */
  } >AXIRAM
}
