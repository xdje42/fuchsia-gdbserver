/* Decoder using libipt for simple-pt */

/*
 * Copyright (c) 2015, Intel Corporation
 * Author: Andi Kleen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#define _GNU_SOURCE 1

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>

#include <vector>
#include <string>

#include <intel-pt.h>

#include "lib/ftl/command_line.h"
#include "lib/ftl/log_settings.h"
#include "lib/ftl/logging.h"

#include "map.h"
#include "symtab.h"
#include "state.h"

#ifdef HAVE_UDIS86
#include <udis86.h>
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define container_of(ptr, type, member)                 \
  ((type *)((char *)(ptr) - offsetof(type, member)))

static bool abstime;
static bool dump_pc;
static bool dump_insn;

/* Includes branches and anything with a time. Always
 * flushed on any resyncs.
 */
struct sinsn {
  uint64_t tic;
  uint64_t ip;
  uint64_t dst; /* For calls */
  uint64_t ts;
  enum pt_insn_class iclass;
  unsigned insn_delta;
  bool loop_start, loop_end;
  unsigned iterations;
  uint32_t ratio;
  uint64_t cr3;
  unsigned speculative : 1, aborted : 1, committed : 1,
    disabled : 1, enabled : 1, resumed : 1,
    interrupted : 1, resynced : 1;
};

#define NINSN 256

static void transfer_events(struct sinsn *si, struct pt_insn *insn)
{
#define T(x) si->x = insn->x;
  T(speculative);
  T(aborted);
  T(committed);
  T(disabled);
  T(enabled);
  T(resumed);
  T(interrupted);
  T(resynced);
#undef T
}

static void print_ip(uint64_t ip, uint64_t cr3, bool print_cr3);

static void print_ev(const char *name, struct sinsn *insn)
{
  printf("%s ", name);
  print_ip(insn->ip, insn->cr3, true);
  putchar('\n');
}

static void print_event(struct sinsn *insn)
{
#if 0 /* Until these flags are reliable in libipt... */
  if (insn->disabled)
    print_ev("disabled", insn);
  if (insn->enabled)
    print_ev("enabled", insn);
  if (insn->resumed)
    print_ev("resumed", insn);
#endif
  if (insn->interrupted)
    print_ev("interrupted", insn);
  if (insn->resynced)
    print_ev("resynced", insn);
}

static void print_tsx(struct sinsn *insn, int *prev_spec, int *indent)
{
  if (insn->speculative != *prev_spec) {
    *prev_spec = insn->speculative;
    printf("%*stransaction\n", *indent, "");
    *indent += 4;
  }
  if (insn->aborted) {
    printf("%*saborted\n", *indent, "");
    *indent -= 4;
  }
  if (insn->committed) {
    printf("%*scommitted\n", *indent, "");
    *indent -= 4;
  }
  if (*indent < 0)
    *indent = 0;
}

static void print_ip(uint64_t ip, uint64_t cr3, bool print_cr3)
{
  struct sym *sym = findsym(ip, cr3);
  if (sym) {
    printf("%s", sym->name);
    if (ip - sym->val > 0)
      printf("+%ld", ip - sym->val);
    if (dump_pc) {
      printf(" [");
      if (print_cr3)
        printf("%lx:", cr3);
      printf("%lx]", ip);
    }
  } else {
    if (print_cr3)
      printf("%lx:", cr3);
    printf("%lx", ip);
  }
}

static double tsc_us(IptDecoderState* state, int64_t t)
{
  if (state->tsc_freq_ == 0)
    return t;
  return (t / (state->tsc_freq_ * 1000));
}

static void print_tic(uint64_t tic)
{
  printf("[%8llu] ", (unsigned long long)tic);
}

static void print_time_indent(void)
{
  printf("%*s", 24, "");
}

static void print_time(IptDecoderState* state, uint64_t ts,
                       uint64_t *last_ts, uint64_t *first_ts)
{
  char buf[30];
  if (!*first_ts && !abstime)
    *first_ts = ts;
  if (!*last_ts)
    *last_ts = ts;
  double rtime = tsc_us(state, ts - *first_ts);
  snprintf(buf, sizeof buf, "%-9.*f [%+-.*f]", state->tsc_freq_ ? 3 : 0,
           rtime,
           state->tsc_freq_ ? 3 : 0,
           tsc_us(state, ts - *last_ts));
  *last_ts = ts;
  printf("%-24s", buf);
}

static const char* insn_class(enum pt_insn_class iclass)
{
  static const char * const class_name[] = {
    [ptic_error] = "error",
    [ptic_other] = "other",
    [ptic_call] = "call",
    [ptic_return] = "ret",
    [ptic_jump] = "jump",
    [ptic_cond_jump] = "cjump",
    [ptic_far_call] = "fcall",
    [ptic_far_return] = "fret",
    [ptic_far_jump] = "fjump",
  };
  return iclass < ARRAY_SIZE(class_name) ? class_name[iclass] : "?";
}

#ifdef HAVE_UDIS86

struct dis {
  ud_t ud_obj;
  uint64_t cr3;
};

static const char *dis_resolve(struct ud *u, uint64_t addr, int64_t *off)
{
  struct dis *d = container_of(u, struct dis, ud_obj);
  struct sym *sym = findsym(addr, d->cr3);
  if (sym) {
    *off = addr - sym->val;
    return sym->name;
  } else
    return NULL;
}

static void init_dis(struct dis *d)
{
  ud_init(&d->ud_obj);
  ud_set_syntax(&d->ud_obj, UD_SYN_ATT);
  ud_set_sym_resolver(&d->ud_obj, dis_resolve);
}

#else

struct dis {};
static void init_dis(struct dis *d) {}

#endif

#define NUM_WIDTH 35

static void print_insn(struct pt_insn *insn, uint64_t total_insncnt,
		       uint64_t ts, struct dis *d, uint64_t cr3)
{
  int i;
  int n;
  printf("[%8llu] %llx %llu %5s insn: ",
         (unsigned long long)total_insncnt,
         (unsigned long long)insn->ip,
         (unsigned long long)ts,
         insn_class(insn->iclass));
  n = 0;
  for (i = 0; i < insn->size; i++)
    n += printf("%02x ", insn->raw[i]);
#ifdef HAVE_UDIS86
  d->cr3 = cr3;
  if (insn->mode == ptem_32bit)
    ud_set_mode(&d->ud_obj, 32);
  else
    ud_set_mode(&d->ud_obj, 64);
  ud_set_pc(&d->ud_obj, insn->ip);
  ud_set_input_buffer(&d->ud_obj, insn->raw, insn->size);
  ud_disassemble(&d->ud_obj);
  printf("%*s%s", NUM_WIDTH - n, "", ud_insn_asm(&d->ud_obj));
#endif
  if (insn->enabled)
    printf("\tENA");
  if (insn->disabled)
    printf("\tDIS");
  if (insn->resumed)
    printf("\tRES");
  if (insn->interrupted)
    printf("\tINT");
  printf("\n");
#if 0 // TODO(dje): use libbacktrace?
  if (dump_dwarf)
    print_addr(find_ip_fn(insn->ip, cr3), insn->ip);
#endif
}

static bool detect_loop = false;

#define NO_ENTRY ((unsigned char)-1)
#define CHASHBITS 8

#define GOLDEN_RATIO_PRIME_64 0x9e37fffffffc0001UL

static int remove_loops(struct sinsn *l, int nr)
{
  int i, j, off;
  unsigned char chash[1 << CHASHBITS];
  memset(chash, NO_ENTRY, sizeof(chash));

  for (i = 0; i < nr; i++) {
    int h = (l[i].ip * GOLDEN_RATIO_PRIME_64) >> (64 - CHASHBITS);

    l[i].iterations = 0;
    l[i].loop_start = l[i].loop_end = false;
    if (chash[h] == NO_ENTRY) {
      chash[h] = i;
    } else if (l[chash[h]].ip == l[i].ip) {
      bool is_loop = true;
      unsigned insn = 0;

      off = 0;
      for (j = chash[h]; j < i && i + off < nr; j++, off++) {
        if (l[j].ip != l[i + off].ip) {
          is_loop = false;
          break;
        }
        insn += l[j].insn_delta;
      }
      if (is_loop) {
        j = chash[h];
        l[j].loop_start = true;
        if (l[j].iterations == 0)
          l[j].iterations++;
        l[j].iterations++;
        printf("loop %llx-%llx %d-%d %u insn iter %d\n", 
               (unsigned long long)l[j].ip, 
               (unsigned long long)l[i].ip,
               j, i,
               insn, l[j].iterations);
        memmove(l + i, l + i + off,
                (nr - (i + off)) * sizeof(struct sinsn));
        l[i-1].loop_end = true;
        nr -= off;
      }
    }
  }
  return nr;
}

struct local_pstate {
  int indent;
  int prev_spec;
};

struct global_pstate {
  uint64_t last_ts;
  uint64_t first_ts;
  unsigned ratio;
};

static void print_loop(struct sinsn *si, struct local_pstate *ps)
{
  if (si->loop_start) {
    print_tic(si->tic);
    print_time_indent();
    printf(" %5s  %*sloop start %u iterations ", "", ps->indent, "", si->iterations);
    print_ip(si->ip, si->cr3, true);
    putchar('\n');
  }
  if (si->loop_end) {
    print_tic(si->tic);
    print_time_indent();
    printf(" %5s  %*sloop end ", "", ps->indent, "");
    print_ip(si->ip, si->cr3, true);
    putchar('\n');
  }
}

static void print_output(IptDecoderState* state,
                         struct sinsn *insnbuf, int sic,
                         struct local_pstate *ps,
                         struct global_pstate *gps)
{
  int i;
  for (i = 0; i < sic; i++) {
    struct sinsn *si = &insnbuf[i];

    if (si->speculative || si->aborted || si->committed)
      print_tsx(si, &ps->prev_spec, &ps->indent);
    if (si->ratio && si->ratio != gps->ratio) {
      printf("frequency %d\n", si->ratio);
      gps->ratio = si->ratio;
    }
    if (si->disabled || si->enabled || si->resumed ||
        si->interrupted || si->resynced)
      print_event(si);
    if (detect_loop && (si->loop_start || si->loop_end))
      print_loop(si, ps);
    switch (si->iclass) {
    case ptic_far_call:
    case ptic_call: {
      print_tic(si->tic);
      if (si->ts)
        print_time(state, si->ts, &gps->last_ts, &gps->first_ts);
      else
        print_time_indent();
      printf("[+%4u] %*s", si->insn_delta, ps->indent, "");
      print_ip(si->ip, si->cr3, true);
      printf(" -> ");
      print_ip(si->dst, si->cr3, false);
      putchar('\n');
      ps->indent += 4;
      break;
    }
    case ptic_far_return:
    case ptic_return:
      ps->indent -= 4;
      if (ps->indent < 0)
        ps->indent = 0;
      /* fallthrough */
    default:
      /* Always print if we have a time (for now) */
      if (si->ts) {
        print_tic(si->tic);
        print_time(state, si->ts, &gps->last_ts, &gps->first_ts);
        printf("[+%4u] %*s", si->insn_delta, ps->indent, "");
        print_ip(si->ip, si->cr3, true);
        putchar('\n');
      }
      break;
    }
  }
}

static int decode(IptDecoderState* state)
{
  struct pt_insn_decoder *decoder = state->decoder_;
  struct global_pstate gps = { };
  uint64_t last_ts = 0;
  struct local_pstate ps;
  struct dis dis;

  gps.first_ts = 0;
  gps.last_ts = 0;

  /* this doesn't need to be accurate, it's just to generate
     referenceable numbers in the output */
  uint64_t total_insncnt = 0;

  init_dis(&dis);
  for (;;) {
    uint64_t pos;
    int err = pt_insn_sync_forward(decoder);
    if (err < 0) {
      pt_insn_get_offset(decoder, &pos);
      printf("%llx: sync forward: %s\n",
             (unsigned long long)pos,
             pt_errstr(pt_errcode(err)));
      break;
    }

    memset(&ps, 0, sizeof(struct local_pstate));

    unsigned long insncnt = 0;
    struct sinsn insnbuf[NINSN];
    uint64_t errcr3 = 0;
    uint64_t errip = 0;
    uint32_t prev_ratio = 0;
    do {
      int sic = 0;
      while (!err && sic < NINSN - 1) {
        struct pt_insn insn;
        struct sinsn *si = &insnbuf[sic];

        total_insncnt++;

        insn.ip = 0;
        pt_insn_time(decoder, &si->ts, NULL, NULL);
        err = pt_insn_next(decoder, &insn, sizeof(struct pt_insn));
        if (err < 0) {
          pt_insn_get_cr3(decoder, &errcr3);
          errip = insn.ip;
          break;
        }
        // XXX use lost counts
        pt_insn_get_cr3(decoder, &si->cr3);
        if (dump_insn)
          print_insn(&insn, total_insncnt, si->ts, &dis, si->cr3);
        insncnt++;
        uint32_t ratio;
        si->ratio = 0;
        pt_insn_core_bus_ratio(decoder, &ratio);
        if (ratio != prev_ratio) {
          si->ratio = ratio;
          prev_ratio = ratio;
        }
        /* This happens when -K is used. Match everything for now. */
        if (si->cr3 == -1UL)
          si->cr3 = 0;
        if (si->ts && si->ts == last_ts)
          si->ts = 0;
        si->iclass = insn.iclass;
        if (insn.iclass == ptic_call || insn.iclass == ptic_far_call) {
          si->tic = total_insncnt;
          si->ip = insn.ip;
          err = pt_insn_next(decoder, &insn, sizeof(struct pt_insn));
          if (err < 0) {
            si->dst = 0;
            pt_insn_get_cr3(decoder, &errcr3);
            errip = insn.ip;
            break;
          }
          si->dst = insn.ip;
          if (!si->ts) {
            pt_insn_time(decoder, &si->ts, NULL, NULL);
            if (si->ts && si->ts == last_ts)
              si->ts = 0;
          }
          si->insn_delta = insncnt;
          insncnt = 1;
          sic++;
          transfer_events(si, &insn);
        } else if (insn.iclass == ptic_return || insn.iclass == ptic_far_return || si->ts ||
                   insn.enabled || insn.disabled || insn.resumed || insn.interrupted ||
                   insn.resynced || insn.stopped || insn.aborted) {
          si->tic = total_insncnt;
          si->ip = insn.ip;
          si->insn_delta = insncnt;
          insncnt = 0;
          sic++;
          transfer_events(si, &insn);
        } else
          continue;
        if (si->ts)
          last_ts = si->ts;
      }

      if (detect_loop)
        sic = remove_loops(insnbuf, sic);
      print_output(state, insnbuf, sic, &ps, &gps);
    } while (err == 0);
    if (err == -pte_eos)
      break;
    pt_insn_get_offset(decoder, &pos);
    printf("[%8llu] %llx:%llx:%llx: error %s\n",
           (unsigned long long)total_insncnt,
           (unsigned long long)pos,
           (unsigned long long)errcr3,
           (unsigned long long)errip,
           pt_errstr(pt_errcode(err)));
  }
  return 0;
}

static void print_header(void)
{
  printf("%-10s %-9s %-13s %-7s %s\n",
         "REF#",
         "TIME",
         "DELTA",
         "INSNs",
         "OPERATION");
}

static constexpr char usage_string[] =
  "sptdecode --pt ptfile --elf elffile ...\n"
  "\n"
  "These options are required:\n"
  "\n"
  "--pt/-p ptfile     PT input file. Required\n"
  "--cpuid/-C file    Name of the .cpuid file (sideband data)\n"
  "--ids/-I file      An \"ids.txt\" file, which provides build-id\n"
  "                   to debug-info-containing ELF file (sideband data)\n"
  "                   May be specified multiple times.\n"
  "--ktrace/-K file   Name of the .ktrace file (sideband data)\n"
  "--map/-M file      Name of file containing mappings of ELF files to their\n"
  "                   load addresses (sideband data)\n"
  "                   May be specified multiple times.\n"
  "\n"
  "The remaining options are, umm, optional.\n"
  "\n"
  "--elf/-e binary[:codebin]  ELF input PT files\n"
  "                   When codebin is specified read code from codebin.\n"
  "                   May be specified multiple times.\n"
  "kernel file/-k     Name of the kernel ELF file\n"
  "--pc/-c            Dump numeric instruction addresses\n"
  "--insn/-i          Dump instruction bytes\n"
  "--tsc/-t	      Print time as TSC\n"
  "--abstime/-a	      Print absolute time instead of relative to trace\n"
  "--verbose=N        Set verbosity to N\n"
#if 0 // needs more debugging
  fprintf(stderr, "--loop/-l	  detect loops\n"
#endif
  ;

static void usage(void)
{
  fprintf(stderr, "%s", usage_string);
  exit(1);
}

struct option opts[] = {
  { "abstime", no_argument, NULL, 'a' },
  { "elf", required_argument, NULL, 'e' },
  { "pt", required_argument, NULL, 'p' },
  { "pc", no_argument, NULL, 'c' },
  { "insn", no_argument, NULL, 'i' },
#if 0 // needs more debugging
  { "loop", no_argument, NULL, 'l' },
#endif
  { "tsc", no_argument, NULL, 't' },
  { "kernel", required_argument, NULL, 'k' },
  { "cpuid", required_argument, NULL, 'C' },
  { "ids", required_argument, NULL, 'I' },
  { "ktrace", required_argument, NULL, 'K' },
  { "map", required_argument, NULL, 'M' },
  { "verbose", required_argument, NULL, 'v' },
  { }
};

int main(int argc, char **argv)
{
  auto state = new IptDecoderState();
  int c;
  bool use_tsc_time = false;
  const char* pt_file = NULL;
  const char* kernel_file = NULL;
  const char* cpuid_file = NULL;
  const char* ktrace_file = NULL;
  std::vector<const char*> elf_files;
  std::vector<const char*> ids_files;
  std::vector<const char*> map_files;

  ftl::CommandLine cl = ftl::CommandLineFromArgcArgv(argc, argv);
  if (!ftl::SetLogSettingsFromCommandLine(cl))
    return EXIT_FAILURE;

  while ((c = getopt_long(argc, argv, "ae:p:is:ltdk:C:I:K:M:", opts, NULL)) != -1) {
    switch (c) {
    case 'a':
      abstime = true;
      break;
    case 'e':
      elf_files.push_back(optarg);
      break;
    case 'p':
      /* FIXME */
      if (pt_file) {
        fprintf(stderr, "Only one PT file supported\n");
        usage();
      }
      pt_file = optarg;
      break;
    case 'c':
      dump_pc = true;
      break;
    case 'i':
      dump_insn = true;
      break;
    case 'l':
      detect_loop = true;
      break;
    case 't':
      use_tsc_time = true;
      break;
    case 'k':
      kernel_file = optarg;
      break;
    case 'C':
      cpuid_file = optarg;
      break;
    case 'I':
      ids_files.push_back(optarg);
      break;
    case 'K':
      ktrace_file = optarg;
      break;
    case 'M':
      map_files.push_back(optarg);
      break;
    case 'v':
      // already handled
      break;
    default:
      usage();
    }
  }

  if (argc - optind != 0)
    usage();
  if (!pt_file)
    usage();
  if (!cpuid_file || ids_files.size() == 0 || !ktrace_file ||
      map_files.size() == 0)
    usage();

  if (!state->AllocDecoder(pt_file))
    exit(1);

  if (!state->AllocImage("simple-pt"))
    exit(1);

  // Read sideband data before we read anything else.

  if (!state->ReadCpuidFile(cpuid_file))
    exit(1);

  for (auto f : ids_files) {
    if (!state->ReadIdsFile(f))
      exit(1);
  }

  if (!state->ReadKtraceFile(ktrace_file))
    exit(1);

  for (auto f : map_files) {
    if (!state->ReadMapFile(f))
      exit(1);
  }

  for (auto f : ids_files) {
    if (!state->ReadIdsFile(f))
      exit(1);
  }

  for (auto f : elf_files) {
    // FIXME: This isn't useful without base addr, etc.
    if (!state->ReadElf(f, 0, 0, 0, 0))
      exit(1);
  }

  if (kernel_file) {
    if (!state->ReadStaticElf(kernel_file))
      exit(1);
  }

  if (use_tsc_time)
    state->tsc_freq_ = 0;

  print_header();

  decode(state);

  delete state;

  return 0;
}
