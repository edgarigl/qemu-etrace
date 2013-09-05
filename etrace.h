enum {
    TYPE_EXEC = 1,
    TYPE_TB = 2,
    TYPE_NOTE = 3,
    TYPE_MEM = 4,
    TYPE_ARCH = 5,
    TYPE_INFO = 0x4554,
};

struct etrace_hdr {
    uint16_t type;
    union {
        uint16_t unit_id;
    };
    uint32_t len;
};

enum etrace_info_flags {
    ETRACE_INFO_F_TB_CHAINING   = (1 << 0),
};

struct etrace_info_data {
    uint64_t attr;
    struct {
        uint16_t major;
        uint16_t minor;
    } version;
};

struct etrace_arch {
    struct {
        uint32_t arch_id;
        uint8_t arch_bits;
        uint8_t big_endian;
    } guest, host;
};

struct etrace_entry32 {
    uint32_t duration;
    uint32_t start, end;
};

struct etrace_entry64 {
    uint32_t duration;
    uint64_t start, end;
};

struct etrace_exec {
    uint64_t start_time;
    union {
        struct etrace_entry32 t32[0];
        struct etrace_entry64 t64[0];
    };
};

struct etrace_note {
    uint64_t time;
    uint8_t data8[0];
};

enum etrace_mem_attr {
    MEM_READ    = (0 << 0),
    MEM_WRITE   = (1 << 0),
};

struct etrace_mem {
    uint64_t time;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t value;
    uint32_t attr;
    uint8_t size;
    uint8_t padd[3];
};

struct etrace_tb {
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t host_addr;
    uint32_t guest_code_len;
    uint32_t host_code_len;
    uint8_t data8[0];
};

struct etrace_pkg {
	struct etrace_hdr hdr;
	union {
		struct etrace_info_data info;
		struct etrace_arch arch;
		struct etrace_exec ex;
		struct etrace_tb tb;
		struct etrace_note note;
		struct etrace_mem mem;
		uint8_t   u8[0];
		uint16_t u16[0];
		uint32_t u32[0];
		uint64_t u64[0];
	};
};

void etrace_show(int fd, FILE *fp_out,
                 const char *objdump, const char *machine,
                 const char *guest_objdump, const char *guest_machine,
                 void **sym_tree, enum cov_format cov_fmt);
