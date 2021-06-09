#include <jni.h>
#include <string>
#include <android/log.h>
#include <link.h>
#include <map>
#include <cstring>
#include <elf.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define PAGE_SIZE 4096
#define PAGE_START(a) ((a) & ~(PAGE_SIZE-1))
#if defined(__LP64__)
#define ELFW(what) ELF64_ ## what

#define Elf_Dyn Elf64_Dyn
#define Elf_Sym Elf64_Sym
#define Elf_Rela Elf64_Rela
#else
#define ELFW(what) ELF32_ ## what
#define Elf_Dyn Elf32_Dyn
#define Elf_Sym Elf32_Sym
#define Elf_Rela Elf32_Rela

#endif

#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)
#define ELF64_R_SYM(i) ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)

using namespace std;

const char *myStrstr(const char *src, const char *sub) {
    __android_log_print(ANDROID_LOG_DEBUG, "Mrack", "src:%s ,sub %s", src, sub);

    const char *bp;
    const char *sp;
    if (!src || !sub) {
        return src;
    }
    /* 遍历src字符串  */
    while (*src) {
        /* 用来遍历子串 */
        bp = src;
        sp = sub;
        do {
            if (!*sp)  /*到了sub的结束位置，返回src位置   */
                return src;
        } while (*bp++ == *sp++);
        src++;
    }
    return NULL;
}

static int callback(struct dl_phdr_info *info,
                    size_t size, void *data) {
    auto *pInfo = new struct dl_phdr_info(*info);
    if (strstr(pInfo->dlpi_name, "libnative-lib.so")) {
        for (int i = 0; i < pInfo->dlpi_phnum; ++i) {
            const auto *phdr = &(pInfo->dlpi_phdr[i]);
            __u8 *str_table = nullptr;
            Elf_Rela *jmprel = nullptr;
            Elf_Sym *sym_table = nullptr;
            if (phdr->p_type == PT_DYNAMIC) {
                auto *dyn = (Elf_Dyn *) (phdr->p_vaddr + pInfo->dlpi_addr);
                int i1 = 1;
                while (dyn->d_tag) {
                    if (dyn->d_tag == DT_STRTAB) {
                        str_table = (__u8 *) (dyn->d_un.d_ptr + pInfo->dlpi_addr);;
                    }
                    if (dyn->d_tag == DT_JMPREL) {
                        jmprel = (Elf_Rela *) (dyn->d_un.d_ptr + pInfo->dlpi_addr);
                    }
                    if (dyn->d_tag == DT_SYMTAB) {
                        sym_table = (Elf_Sym *) (dyn->d_un.d_ptr + pInfo->dlpi_addr);
                    }

                    dyn = reinterpret_cast<Elf_Dyn *>(phdr->p_vaddr + pInfo->dlpi_addr +
                                                      sizeof(Elf_Dyn) * i1++);
                }
                if (jmprel && str_table && sym_table) {
                    for (int j = 0; jmprel->r_info; ++j) {
                        ElfW(Word) type = ELFW(R_TYPE)(jmprel[j].r_info);
                        ElfW(Word) sym = ELFW(R_SYM)(jmprel[j].r_info);
                        char *name = (char *) (sym_table[sym].st_name + str_table);
                        if (strstr(name, "strstr")) {
                            void *i2 = (void *) (jmprel[j].r_offset + pInfo->dlpi_addr);
                            ElfW(Addr) page_start = PAGE_START(
                                    jmprel[j].r_offset + pInfo->dlpi_addr);
                            mprotect((ElfW(Addr) *) page_start, PAGE_SIZE, PROT_WRITE | PROT_READ);

                            *((ElfW(Addr) *) i2) = (ElfW(Addr)) myStrstr + jmprel[i].r_addend;
                            mprotect((ElfW(Addr) *) page_start, PAGE_SIZE, PROT_READ);
                            __android_log_print(ANDROID_LOG_DEBUG, "module", "name:%s",
                                                sym_table[sym].st_name + str_table);


                            break;
                        }
                    }

                }


            }
        }
    }

    __android_log_print(ANDROID_LOG_DEBUG, "module", "%s", pInfo->dlpi_name);
    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example1_gothook_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    dl_iterate_phdr(&callback, nullptr);
    strstr("test1", "test2");
    return env->NewStringUTF(hello.c_str());
}
