// Minimal ft_* upload test against stock or open plugin.
// Build: cc -o ft_upload_test tools/ft_upload_test.c -ldl -lpthread
//
// Environment (required unless OBN_FT_URL is set):
//   OBN_PRINTER_IP     printer LAN IP
//   OBN_ACCESS_CODE    LAN access code
//
// Environment (optional):
//   OBN_FT_URL         file holding a full bambu:/// tunnel URL on its first
//                      line (e.g. a TUTK URL written by
//                      `plugin_runner --camera-url-out`); overrides the LAN URL
//   OBN_FT_JOB         raw ft_job_create JSON; overrides the default upload
//                      job (then local_file_path is unused)
//   OBN_FT_OUT         write the result's binary payload to this path
//
// Usage:
//   OBN_PRINTER_IP=192.168.1.10 OBN_ACCESS_CODE=abcd1234 \
//     ./ft_upload_test [libbambu_networking.so] [local_file_path]
#include <dlfcn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int ft_err;
typedef struct FT_TunnelHandle FT_TunnelHandle;
typedef struct FT_JobHandle FT_JobHandle;

typedef struct {
    int ec;
    int resp_ec;
    const char* json;
    const void* bin;
    unsigned bin_size;
} ft_job_result;

typedef struct {
    int kind;
    const char* json;
} ft_job_msg;

typedef ft_err (*fn_create)(const char*, FT_TunnelHandle**);
typedef ft_err (*fn_sync_connect)(FT_TunnelHandle*);
typedef ft_err (*fn_job_create)(const char*, FT_JobHandle**);
typedef ft_err (*fn_start_job)(FT_TunnelHandle*, FT_JobHandle*);
typedef ft_err (*fn_set_result_cb)(FT_JobHandle*, void (*)(void*, ft_job_result), void*);
typedef ft_err (*fn_set_msg_cb)(FT_JobHandle*, void (*)(void*, ft_job_msg), void*);
typedef void (*fn_release_tunnel)(FT_TunnelHandle*);
typedef void (*fn_release_job)(FT_JobHandle*);

static const char* default_plugin_path(void)
{
    const char* home = getenv("HOME");
    static char path[512];
    if (home && home[0]) {
        snprintf(path, sizeof(path),
                 "%s/.config/BambuStudio/plugins/libbambu_networking.so", home);
        return path;
    }
    return "libbambu_networking.so";
}

static const char* env_or(const char* name)
{
    const char* v = getenv(name);
    return (v && v[0]) ? v : NULL;
}

static atomic_int g_done;
static int g_ec, g_resp_ec;

static void* require_sym(void* handle, const char* name)
{
    dlerror();
    void* sym = dlsym(handle, name);
    const char* err = dlerror();
    if (err || !sym) {
        fprintf(stderr, "dlsym(%s): %s\n", name, err ? err : "missing symbol");
        return NULL;
    }
    return sym;
}

static void on_result(void* user, ft_job_result r)
{
    (void)user;
    g_ec = r.ec;
    g_resp_ec = r.resp_ec;
    printf("result ec=%d resp_ec=%d bin=%u json=%s\n", r.ec, r.resp_ec,
           r.bin_size, r.json ? r.json : "");
    const char* out = env_or("OBN_FT_OUT");
    if (out && r.bin && r.bin_size) {
        FILE* f = fopen(out, "wb");
        if (f) {
            fwrite(r.bin, 1, r.bin_size, f);
            fclose(f);
        }
    }
    atomic_store_explicit(&g_done, 1, memory_order_release);
}

// Reads the first line of `path` into `buf`; returns 0 on success.
static int read_url_file(const char* path, char* buf, size_t len)
{
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    const int ok = fgets(buf, (int)len, f) != NULL;
    fclose(f);
    if (!ok) return -1;
    buf[strcspn(buf, "\r\n")] = '\0';
    return buf[0] ? 0 : -1;
}

static void on_msg(void* user, ft_job_msg msg)
{
    (void)user;
    printf("msg kind=%d json=%s\n", msg.kind, msg.json ? msg.json : "");
}

int main(int argc, char** argv)
{
    const char* ip = env_or("OBN_PRINTER_IP");
    const char* code = env_or("OBN_ACCESS_CODE");
    const char* url_file = env_or("OBN_FT_URL");
    if (!url_file && (!ip || !code)) {
        fprintf(stderr,
                "Set OBN_PRINTER_IP and OBN_ACCESS_CODE or OBN_FT_URL "
                "(see tools/ft_upload_test.c header).\n");
        return 1;
    }

    const char* so = argc > 1 ? argv[1] : default_plugin_path();
    const char* path = argc > 2 ? argv[2] : "/tmp/obn_test_upload.bin";

    char url[4096];
    if (url_file) {
        if (read_url_file(url_file, url, sizeof(url)) != 0) {
            fprintf(stderr, "cannot read a URL from %s\n", url_file);
            return 1;
        }
    } else {
        snprintf(url, sizeof(url),
                 "bambu:///local/%s?port=6000&user=bblp&passwd=%s", ip, code);
    }

    void* h = dlopen(so, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    fn_create create = (fn_create)require_sym(h, "ft_tunnel_create");
    fn_sync_connect sync = (fn_sync_connect)require_sym(h, "ft_tunnel_sync_connect");
    fn_job_create job_create = (fn_job_create)require_sym(h, "ft_job_create");
    fn_start_job start_job = (fn_start_job)require_sym(h, "ft_tunnel_start_job");
    fn_set_result_cb set_res = (fn_set_result_cb)require_sym(h, "ft_job_set_result_cb");
    fn_set_msg_cb set_msg = (fn_set_msg_cb)require_sym(h, "ft_job_set_msg_cb");
    fn_release_tunnel rel_t = (fn_release_tunnel)require_sym(h, "ft_tunnel_release");
    fn_release_job rel_j = (fn_release_job)require_sym(h, "ft_job_release");
    if (!create || !sync || !job_create || !start_job || !set_res || !set_msg ||
        !rel_t || !rel_j) {
        dlclose(h);
        return 1;
    }

    FT_TunnelHandle* tunnel = NULL;
    if (create(url, &tunnel) != 0 || !tunnel) {
        fprintf(stderr, "create failed\n");
        dlclose(h);
        return 1;
    }
    if (sync(tunnel) != 0) {
        fprintf(stderr, "sync_connect failed\n");
        rel_t(tunnel);
        dlclose(h);
        return 1;
    }

    char params[1024];
    const char* job_json = env_or("OBN_FT_JOB");
    if (job_json) {
        snprintf(params, sizeof(params), "%s", job_json);
    } else {
        snprintf(params, sizeof(params),
                 "{\"cmd_type\":5,\"dest_name\":\"ft_test.bin\",\"dest_storage\":\"emmc\","
                 "\"file_path\":\"%s\"}",
                 path);
    }

    FT_JobHandle* job = NULL;
    if (job_create(params, &job) != 0 || !job) {
        fprintf(stderr, "job_create failed\n");
        rel_t(tunnel);
        dlclose(h);
        return 1;
    }
    set_res(job, on_result, NULL);
    set_msg(job, on_msg, NULL);
    start_job(tunnel, job);

    for (int i = 0; i < 300 &&
                    !atomic_load_explicit(&g_done, memory_order_acquire);
         ++i) {
        usleep(100000);
    }

    if (!atomic_load_explicit(&g_done, memory_order_acquire)) {
        printf("timeout waiting for result\n");
    }
    rel_j(job);
    rel_t(tunnel);
    dlclose(h);
    return atomic_load_explicit(&g_done, memory_order_acquire)
               ? (g_ec == 0 ? 0 : 2)
               : 3;
}
