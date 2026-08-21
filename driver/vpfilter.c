#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#define BUF_SIZE 65536
#define PYTHON_BIN       "/usr/bin/python3"
#define LEAKTRACE_SCRIPT "/home/vboxuser/Desktop/leaktrace/process_job.py"
#define TEMP_DIR         "/tmp"

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    if (argc < 6) {
        fprintf(stderr, "ERROR: Invalid filter arguments\n");
        return 1;
    }

    const char *job_id  = argv[1];
    const char *user    = argv[2];
    const char *title   = argv[3];
    (void)argv[4]; /* copies - unused */
    (void)argv[5]; /* options - unused */

    fprintf(stderr, "INFO: vpfilter (LeakTrace) started\n");
    fprintf(stderr, "INFO: job_id=%s user=%s title=%s\n", job_id, user, title);

    /* ── 1. Read input into temp file ── */
    char tmp_input[256];
    snprintf(tmp_input, sizeof(tmp_input), "%s/lt_in_%s.pdf", TEMP_DIR, job_id);

    FILE *in = stdin;
    if (argc >= 7 && argv[6] && strlen(argv[6]) > 0) {
        in = fopen(argv[6], "rb");
        if (!in) {
            fprintf(stderr, "ERROR: Cannot open input %s: %s\n", argv[6], strerror(errno));
            return 1;
        }
    }

    FILE *tmp_f = fopen(tmp_input, "wb");
    if (!tmp_f) {
        fprintf(stderr, "ERROR: Cannot create temp file: %s\n", strerror(errno));
        if (in != stdin) fclose(in);
        return 1;
    }

    unsigned char buffer[BUF_SIZE];
    while (1) {
        size_t n = fread(buffer, 1, sizeof(buffer), in);
        if (n > 0) fwrite(buffer, 1, n, tmp_f);
        if (n < sizeof(buffer)) {
            if (feof(in)) break;
            if (ferror(in)) {
                fprintf(stderr, "ERROR: Read failed\n");
                fclose(tmp_f);
                if (in != stdin) fclose(in);
                return 1;
            }
        }
    }
    fclose(tmp_f);
    if (in != stdin) fclose(in);

    /* ── 2. Call LeakTrace: watermark + encrypt + log ── */
    char tmp_output[256];
    snprintf(tmp_output, sizeof(tmp_output), "%s/lt_out_%s.pdf", TEMP_DIR, job_id);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "%s %s \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" 1>&2",
        PYTHON_BIN, LEAKTRACE_SCRIPT,
        tmp_input, tmp_output,
        job_id, user, title);

    fprintf(stderr, "INFO: Calling LeakTrace...\n");
    int ret = system(cmd);

    if (ret != 0 || access(tmp_output, F_OK) != 0) {
        fprintf(stderr, "WARNING: LeakTrace failed (code %d), passing original\n", ret);
        snprintf(tmp_output, sizeof(tmp_output), "%s", tmp_input);
    } else {
        fprintf(stderr, "INFO: LeakTrace processing OK\n");
    }

    /* ── 3. Stream processed PDF to stdout → vpbackend ── */
    FILE *out_f = fopen(tmp_output, "rb");
    if (!out_f) {
        fprintf(stderr, "ERROR: Cannot open output file: %s\n", strerror(errno));
        unlink(tmp_input);
        return 1;
    }

    while (1) {
        size_t n = fread(buffer, 1, sizeof(buffer), out_f);
        if (n > 0) {
            if (fwrite(buffer, 1, n, stdout) != n) {
                fprintf(stderr, "ERROR: Write to stdout failed\n");
                fclose(out_f);
                unlink(tmp_input);
                return 1;
            }
        }
        if (n < sizeof(buffer)) break;
    }
    fclose(out_f);
    fflush(stdout);

    /* ── 4. Cleanup ── */
    unlink(tmp_input);
    unlink(tmp_output);

    fprintf(stderr, "INFO: vpfilter (LeakTrace) done\n");
    return 0;
}
