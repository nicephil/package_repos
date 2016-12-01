#ifndef __NMSC_JSON_ENTRY_H__
#define __NMSC_JSON_ENTRY_H__

typedef struct dc_json_entry {
    int order;
    char *key;
    int (*json_handler)(struct json_object *obj, const char *key);
} dc_json_entry;

extern int dc_hdl_entry_singleobj(struct json_object *obj, const char *obj_key);
extern int dc_hdl_entry_multiobj(struct json_object *obj, const char *obj_key);    
#endif
