#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>

#define OUTDIR "/var/spool/virtprinter"
#define BUF_SIZE 65536

static void sanitize(const char *in, char *out, size_t size) {
    size_t j = 0;
    if (!in || !*in) in = "untitled";

    for (size_t i = 0; in[i] && j + 1 < size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '.' || c == '-' || c == '_')
            out[j++] = c;
        else
            out[j++] = '_';
    }

    if (j == 0 && size > 1) {
        strncpy(out, "untitled", size - 1);
        out[size - 1] = '\0';
        return;
    }

    out[j] = '\0';
}

static void json_string(FILE *f, const char *s) {
    fputc('"', f);
    if (s) {
        for (size_t i = 0; s[i]; i++) {
            if (s[i] == '"' || s[i] == '\\')
                fprintf(f, "\\%c", s[i]);
            else if (s[i] == '\n')
                fprintf(f, "\\n");
            else if (s[i] == '\r')
                fprintf(f, "\\r");
            else if (s[i] == '\t')
                fprintf(f, "\\t");
            else
                fputc(s[i], f);
        }
    }
    fputc('"', f);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    if (argc == 1) {
        printf("direct virtprinter:/ \"Mahesh\" \"Mahesh Virtual Printer\" \"MFG:Mahesh;MDL:VirtualPrinter;CLS:PRINTER;\"\n");
        return 0;
    }

    if (argc < 6) {
        fprintf(stderr, "ERROR: Invalid backend arguments\n");
        return 1;
    }

    const char *job_id = argv[1];
    const char *user = argv[2];
    const char *title = argv[3];
    const char *copies = argv[4];
    const char *options = argv[5];

    char safe_title[128];
    sanitize(title, safe_title, sizeof(safe_title));

    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", &tm_now);

    char base_path[512];
    snprintf(base_path, sizeof(base_path), "%s/job_%s_%s_%s", OUTDIR, job_id, timestamp, safe_title);

    char data_path[600];
    char meta_path[600];

    snprintf(data_path, sizeof(data_path), "%s.pdf", base_path);
    snprintf(meta_path, sizeof(meta_path), "%s.json", base_path);

    FILE *out = fopen(data_path, "wb");
    if (!out) {
        fprintf(stderr, "ERROR: Cannot create output file %s: %s\n", data_path, strerror(errno));
        return 1;
    }

    unsigned char buffer[BUF_SIZE];
    size_t total = 0;

    while (1) {
        size_t n = fread(buffer, 1, sizeof(buffer), stdin);

        if (n > 0) {
            if (fwrite(buffer, 1, n, out) != n) {
                fprintf(stderr, "ERROR: Write failed: %s\n", strerror(errno));
                fclose(out);
                return 1;
            }
            total += n;
        }

        if (n < sizeof(buffer)) {
            if (feof(stdin)) break;
            if (ferror(stdin)) {
                fprintf(stderr, "ERROR: Read failed\n");
                fclose(out);
                return 1;
            }
        }
    }

    fclose(out);
    chmod(data_path, 0644);

    FILE *meta = fopen(meta_path, "w");
    if (meta) {
        fprintf(meta, "{\n");
        fprintf(meta, "  \"job_id\": ");
        json_string(meta, job_id);
        fprintf(meta, ",\n  \"user\": ");
        json_string(meta, user);
        fprintf(meta, ",\n  \"title\": ");
        json_string(meta, title);
        fprintf(meta, ",\n  \"copies\": ");
        json_string(meta, copies);
        fprintf(meta, ",\n  \"options\": ");
        json_string(meta, options);
        fprintf(meta, ",\n  \"printer\": ");
        json_string(meta, getenv("PRINTER"));
        fprintf(meta, ",\n  \"content_type\": ");
        json_string(meta, getenv("CONTENT_TYPE"));
        fprintf(meta, ",\n  \"bytes_saved\": %zu,\n", total);
        fprintf(meta, "  \"output_file\": ");
        json_string(meta, data_path);
        fprintf(meta, "\n}\n");
        fclose(meta);
        chmod(meta_path, 0644);
    }

    fprintf(stderr, "INFO: Virtual printer saved job to %s\n", data_path);
    fprintf(stderr, "INFO: Metadata saved to %s\n", meta_path);

    return 0;
}
