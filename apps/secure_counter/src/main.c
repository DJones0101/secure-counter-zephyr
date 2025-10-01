#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/app_memory/app_memdomain.h>
#include <zephyr/shell/shell.h>
#include <stdlib.h>

LOG_MODULE_REGISTER(secure_counter, LOG_LEVEL_INF);

typedef struct {
    uint32_t seq;
    int64_t  ts_ms;
} msg_t;

/* Public queue (granted to user thread) */
K_MSGQ_DEFINE(counter_q, sizeof(msg_t), 16, 4);

/* Secret queue (NO grant to user thread) — used to demo blocked access */
K_MSGQ_DEFINE(secret_q, sizeof(msg_t), 1, 4);

/* Period */
static atomic_t seq_cnt = ATOMIC_INIT(0);
static uint32_t period_ms = 100;

/* Timer + work for producer path */
static struct k_timer tick_timer;
static void tick_work_handler(struct k_work *work);
K_WORK_DEFINE(tick_work, tick_work_handler);

/* ISR -> schedule privileged work */
static void tick_timer_handler(struct k_timer *timer)
{
    ARG_UNUSED(timer);
    k_work_submit(&tick_work);
}

/* Privileged producer puts into msgq */
static void tick_work_handler(struct k_work *work)
{
    ARG_UNUSED(work);
    msg_t m = {
        .seq   = (uint32_t)atomic_inc(&seq_cnt),
        .ts_ms = k_uptime_get()
    };
    int rc = k_msgq_put(&counter_q, &m, K_NO_WAIT);
    if (rc != 0) {
        LOG_WRN("msgq full; dropped seq=%u", m.seq);
    }
}

/* --- USER-MODE consumer thread --- */
#define CONSUMER_STACK_SIZE 2048
#define CONSUMER_PRIORITY   5
K_THREAD_STACK_DEFINE(consumer_stack, CONSUMER_STACK_SIZE);
static struct k_thread consumer_tid;

static void consumer_thread(void *a, void *b, void *c)
{
    ARG_UNUSED(a); ARG_UNUSED(b); ARG_UNUSED(c);
    msg_t m;
    while (1) {
        if (k_msgq_get(&counter_q, &m, K_FOREVER) == 0) {
            LOG_INF("[USER] got seq=%u at %lld ms", m.seq, m.ts_ms);
        }
    }
}

/* --- Shell commands --- */
static int cmd_counter_get(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    size_t unused = 0;
    (void)k_thread_stack_space_get(&consumer_tid, &unused);
    shell_print(shell, "period=%u ms, seq=%u, user_stack_free=%zu bytes",
                period_ms, (uint32_t)atomic_get(&seq_cnt), unused);
    return 0;
}

static int cmd_counter_set(const struct shell *shell, size_t argc, char **argv)
{
    if (argc != 2) {
        shell_error(shell, "usage: counter set <ms>");
        return -EINVAL;
    }
    char *end = NULL;
    long v = strtol(argv[1], &end, 10);
    if (!argv[1] || *argv[1] == '\0' || (end && *end != '\0') || v < 10 || v > 10000) {
        shell_error(shell, "invalid <ms> (10..10000)");
        return -EINVAL;
    }
    period_ms = (uint32_t)v;
    k_timer_stop(&tick_timer);
    k_timer_start(&tick_timer, K_MSEC(period_ms), K_MSEC(period_ms));
    shell_print(shell, "period set to %u ms", period_ms);
    return 0;
}

/* This simulates a malicious/buggy user thread trying to touch a kernel object
 * it was NOT granted. Expect a fatal permission fault, which is the demo!
 */
static int cmd_attack_try_secret(const struct shell *shell, size_t argc, char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    shell_print(shell, "attempting unauthorized access to secret_q...");
    msg_t m;
    /* User thread has NO permission on secret_q; this call should fault. */
    int rc = k_msgq_get(&secret_q, &m, K_NO_WAIT);
    shell_print(shell, "unexpectedly returned rc=%d (should not happen)", rc);
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
    sub_counter,
    SHELL_CMD(get, NULL, "show current period, seq, and user stack free", cmd_counter_get),
    SHELL_CMD(set, NULL, "set period (ms)", cmd_counter_set),
    SHELL_CMD(attack, NULL, "trigger blocked access to secret_q (expect fault)", cmd_attack_try_secret),
    SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(counter, &sub_counter, "secure_counter controls", NULL);

int main(void)
{
    LOG_INF("secure_counter (userspace + shell + guards) starting...");

    /* Grant user thread access to the PUBLIC msgq only */
    k_object_access_all_grant(&counter_q);
    /* Note: secret_q is intentionally NOT granted. */

    /* Create consumer as USER thread */
    k_tid_t t = k_thread_create(&consumer_tid, consumer_stack,
                                K_THREAD_STACK_SIZEOF(consumer_stack),
                                consumer_thread, NULL, NULL, NULL,
                                CONSUMER_PRIORITY, K_USER, K_NO_WAIT);
    k_thread_name_set(t, "consumer_user");

    /* Start periodic timer using period_ms */
    k_timer_init(&tick_timer, tick_timer_handler, NULL);
    k_timer_start(&tick_timer, K_MSEC(period_ms), K_MSEC(period_ms));

    while (1) {
        k_sleep(K_SECONDS(5));
        LOG_INF("main alive, seq=%u, period=%u ms", (uint32_t)atomic_get(&seq_cnt), period_ms);
    }
}
