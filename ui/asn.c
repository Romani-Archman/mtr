/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#include <errno.h>
#include <string.h>
#include <search.h>

#include <curl/curl.h>
#include <jansson.h>

#include "mtr.h"
#include "asn.h"
#include "dns.h"
#include "utils.h"

/* #define IIDEBUG */
#ifdef IIDEBUG
#include <syslog.h>
#define DEB_syslog syslog
#else
#define DEB_syslog(...) do {} while (0)
#endif

#define IIHASH_HI 128
#define ITEMSMAX 4
#define ITEM_ASN 0
#define ITEM_ORG 1
#define ITEM_COUNTRY 2
#define ITEM_REGION 3
#define ITEM_CITY 4
#define NAMELEN INET6_ADDRSTRLEN
#define IPINFO_URL_FMT "https://ipinfo.io/%s"
#define IPINFO_USER_AGENT "curl/8.19.0"
#define UNKN "???"

static const int iiwidth[] = {
    12, 34, 4, 18, 18
};

typedef char *items_t[ITEMSMAX + 1];

struct ipinfo_response {
    char *data;
    size_t size;
};

struct ipinfo_cache_entry {
    char *key;
    items_t *items;
    struct ipinfo_cache_entry *next;
};

static int iihash = 0;
static bool ipinfo_initialized = false;
static bool curl_initialized = false;
static struct ipinfo_cache_entry *cache_entries;
static char fmtinfo[256];

static size_t curl_write_cb(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp)
{
    struct ipinfo_response *response = userp;
    size_t realsize = size * nmemb;
    char *new_data = realloc(response->data, response->size + realsize + 1);

    if (!new_data)
        return 0;

    response->data = new_data;
    memcpy(response->data + response->size, contents, realsize);
    response->size += realsize;
    response->data[response->size] = '\0';

    return realsize;
}

static char *dup_json_string(
    json_t *obj,
    const char *key)
{
    json_t *value = json_object_get(obj, key);

    if (!json_is_string(value))
        return xstrdup(UNKN);

    return xstrdup(json_string_value(value));
}

static char *extract_asn(
    const char *org)
{
    const char *ptr;
    char *asn;
    size_t len;

    if (!org || strncmp(org, "AS", 2) != 0)
        return xstrdup(UNKN);

    ptr = org + 2;
    while (*ptr && isdigit((unsigned char) *ptr))
        ptr++;

    if (ptr == org + 2)
        return xstrdup(UNKN);

    len = ptr - (org + 2);
    asn = xmalloc(len + 1);
    memcpy(asn, org + 2, len);
    asn[len] = '\0';

    return asn;
}

static void free_items(
    items_t *items)
{
    int i;

    if (!items)
        return;

    for (i = 0; i <= ITEMSMAX; i++)
        free((*items)[i]);

    free(items);
}

static int parse_ipinfo_response(
    items_t *items,
    const char *payload)
{
    json_error_t json_error;
    json_t *root;

    root = json_loads(payload, 0, &json_error);
    if (!root)
        return -1;

    if (!json_is_object(root)) {
        json_decref(root);
        return -1;
    }

    (*items)[ITEM_ORG] = dup_json_string(root, "org");
    (*items)[ITEM_COUNTRY] = dup_json_string(root, "country");
    (*items)[ITEM_REGION] = dup_json_string(root, "region");
    (*items)[ITEM_CITY] = dup_json_string(root, "city");
    (*items)[ITEM_ASN] = extract_asn((*items)[ITEM_ORG]);

    json_decref(root);
    return 0;
}

static char *lookup_item(
    items_t *items,
    int ipinfo_no)
{
    if (ipinfo_no < 0 || ipinfo_no > ITEMSMAX)
        return (*items)[ITEM_ASN];

    if ((*items)[ipinfo_no])
        return (*items)[ipinfo_no];

    return UNKN;
}

static items_t *create_unknown_items(
    void)
{
    items_t *items;
    int i;

    items = xmalloc(sizeof(*items));
    for (i = 0; i <= ITEMSMAX; i++)
        (*items)[i] = xstrdup(UNKN);

    return items;
}

static items_t *ipinfo_lookup(
    const char *ipstr)
{
    CURL *curl;
    CURLcode res;
    long http_status = 0;
    char url[sizeof(IPINFO_URL_FMT) + NAMELEN];
    items_t *items;
    struct ipinfo_response response;

    items = create_unknown_items();

    if (snprintf(url, sizeof(url), IPINFO_URL_FMT, ipstr) >= (int) sizeof(url))
        return items;

    response.data = NULL;
    response.size = 0;

    curl = curl_easy_init();
    if (!curl)
        return items;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, IPINFO_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1000L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2000L);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

    if (res == CURLE_OK && http_status == 200 && response.data) {
        items_t *parsed_items = xmalloc(sizeof(*parsed_items));

        memset(parsed_items, 0, sizeof(*parsed_items));
        if (parse_ipinfo_response(parsed_items, response.data) == 0) {
            free_items(items);
            items = parsed_items;
        } else {
            free(parsed_items);
        }
    } else {
        DEB_syslog(LOG_INFO, "ipinfo lookup failed for %s", ipstr);
    }

    free(response.data);
    curl_easy_cleanup(curl);

    return items;
}

static int ensure_ipinfo_init(
    struct mtr_ctl *ctl)
{
    if (!ipinfo_initialized) {
        ctl->ipinfo_max = ITEMSMAX;

        if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
            error(0, 0, "ipinfo curl init failed");
            return -1;
        }
        curl_initialized = true;

        DEB_syslog(LOG_INFO, "hcreate(%d)", IIHASH_HI);
        if (!(iihash = hcreate(IIHASH_HI)))
            error(0, errno, "ipinfo hash");

        ipinfo_initialized = true;
    }

    return 0;
}

static void add_cache_entry(
    char *key,
    items_t *items)
{
    struct ipinfo_cache_entry *entry;

    entry = xmalloc(sizeof(*entry));
    entry->key = key;
    entry->items = items;
    entry->next = cache_entries;
    cache_entries = entry;
}

static items_t *get_items_for_addr(
    struct mtr_ctl *ctl,
    ip_t *addr)
{
    char key[NAMELEN];
    ENTRY item;
    ENTRY *found_item;
    items_t *items;

    if (!addr)
        return NULL;

    if (ensure_ipinfo_init(ctl) < 0)
        return NULL;

    xstrncpy(key, strlongip(ctl->af, addr), sizeof(key));

    if (iihash) {
        item.key = key;
        found_item = hsearch(item, FIND);
        if (found_item)
            return found_item->data;
    }

    items = ipinfo_lookup(key);
    if (iihash) {
        item.key = xstrdup(key);
        item.data = items;
        if (hsearch(item, ENTER))
            add_cache_entry(item.key, items);
        else {
            free(item.key);
            free_items(items);
            items = create_unknown_items();
        }
    }

    return items;
}

ATTRIBUTE_CONST size_t get_iiwidth_len(
    void)
{
    return (sizeof(iiwidth) / sizeof((iiwidth)[0]));
}

ATTRIBUTE_CONST int get_iiwidth(
    int ipinfo_no)
{
    static const int len = (sizeof(iiwidth) / sizeof((iiwidth)[0]));

    if (ipinfo_no < len)
        return iiwidth[ipinfo_no];
    return iiwidth[ipinfo_no % len];
}

char *fmt_ipinfo(
    struct mtr_ctl *ctl,
    ip_t *addr)
{
    items_t *items;
    char fmt[8];
    char *ipinfo;

    items = get_items_for_addr(ctl, addr);
    ipinfo = items ? lookup_item(items, ctl->ipinfo_no) : UNKN;

    snprintf(fmt, sizeof(fmt), "%s%%-%ds", ctl->ipinfo_no ? "" : "AS",
             get_iiwidth(ctl->ipinfo_no));
    snprintf(fmtinfo, sizeof(fmtinfo), fmt, ipinfo ? ipinfo : UNKN);

    return fmtinfo;
}

int is_printii(
    struct mtr_ctl *ctl)
{
    return (ctl->ipinfo_no >= 0);
}

void asn_open(
    struct mtr_ctl *ctl)
{
    (void) ensure_ipinfo_init(ctl);
}

void asn_close(
    struct mtr_ctl *ctl)
{
    struct ipinfo_cache_entry *entry;

    (void) ctl;

    if (iihash) {
        DEB_syslog(LOG_INFO, "hdestroy()");
        hdestroy();
        iihash = 0;
    }

    while (cache_entries) {
        entry = cache_entries;
        cache_entries = entry->next;
        free(entry->key);
        free_items(entry->items);
        free(entry);
    }

    if (curl_initialized) {
        curl_global_cleanup();
        curl_initialized = false;
    }

    ipinfo_initialized = false;
}
