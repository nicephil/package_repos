#include <services/time_range_services.h>
#include <services/cfg_services.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG(...)

static int time_range_iterator_section(struct uci_section *s, void *arg)
{
    struct uci_element *e;
    //int     flag = 0, ret=0;
    long start, end;
    struct scheme_time_range *scm = NULL;
    struct get_time_range *sp = (struct get_time_range *)arg;
    struct tm tm1, tm2;
    
    if (sp->name[0]!='\0' && strcmp(sp->name, s->e.name)) {
        /*return if  scheme name unmatched*/
        return 0;
    }

    scm = (struct scheme_time_range *)malloc(sizeof(struct scheme_time_range));
    if( scm == NULL ) {
        DEBUG("malloc time_range scheme failed\n");
        return -1;
    }

    memset(scm, 0, sizeof(struct scheme_time_range));
    strncpy(scm->name, s->e.name, sizeof(scm->name) -1);
    uci_foreach_element(&s->options, e) {
        struct uci_option * o = uci_to_option(e);
        if ((o->type != UCI_TYPE_LIST)) {  
            if (strcmp(o->e.name, CFG_TIME_RANGE_ABSTIME) == 0) {
                memset(&tm1, 0, sizeof(struct tm));
                memset(&tm2, 0, sizeof(struct tm));
                sscanf(o->v.string, "%d-%d-%d-%d-%d/%d-%d-%d-%d-%d", 
                    &tm1.tm_year, &tm1.tm_mon, &tm1.tm_mday, &tm1.tm_hour, &tm1.tm_min,
                    &tm2.tm_year, &tm2.tm_mon, &tm2.tm_mday, &tm2.tm_hour, &tm2.tm_min);

                start = mktime(&tm1);
                if(start < 0) {
                    start = 0;
                }
                end = mktime(&tm2);
                if(end < 0) {
                    end = 0;
                }
                if ( (start >= end) && (end != 0) ) {
                    DEBUG("Invalid absolute pair(%s) found in scheme %s, ignore it\n", \
                                        o->v.string, s->e.name);
                } else {
                    /*if we get 0, means no start or no end*/
                    memcpy(&scm->a.start, &tm1, sizeof(struct tm));
                    memcpy(&scm->a.end, &tm2, sizeof(struct tm));
                }
            }
            
        }
        else if ((strcmp(o->e.name, CFG_TIME_RANGE_PERIOD_LIST) == 0)) {
            struct uci_element *e2;
            int count=0;
            struct time_range **tm=&scm->p, *ptr;
            //struct uci_list *l = o->v.list;
            uci_foreach_element(&o->v.list, e2) {
                sscanf(e2->name, "%lu/%lu", &start, &end);
                if ( (start >= end) || (end/86400 >= 7)) {
                    DEBUG("Invalid periodic pair(%s) found in scheme %s, ignore it\n", \
                                        e2->name, s->e.name);
                    continue;
                }
                
                *tm = ptr = (struct time_range *)malloc(sizeof(struct time_range));
                if (ptr == NULL) {
                    DEBUG("malloc periodic time_range failed, current count(%d)\n", count);
                    break;
                }
                memset(ptr, 0, sizeof(struct time_range));
                
                ptr->start.tm_wday = start/86400;
                ptr->start.tm_hour = (start/3600)%24;
                ptr->start.tm_min  = (start/60)%60;
                ptr->end.tm_wday = end/86400;
                ptr->end.tm_hour = (end/3600)%24;
                ptr->end.tm_min  = (end/60)%60;

                tm = &ptr->next;
                count++;
            }
            scm->count = count;
        }
    }
    
    scm->next = sp->scm;
    sp->scm = scm;
    
    return 0;
}

static int time_range_iterator(struct uci_package *p, void *arg)
{
    struct uci_element * e;
    
    uci_foreach_element(&p->sections, e) {
        struct uci_section *s = uci_to_section(e);
        time_range_iterator_section(s, arg);
    }

    return 0;
}

struct scheme_time_range * get_time_range_byname(char *name)
{
    struct get_time_range tp;
    
    memset(&tp, 0, sizeof(struct get_time_range));
    if(name != NULL)
        strcpy(tp.name, name);

    cfg_visit_package(CFG_TIME_RANGE_PACKAGE, time_range_iterator, &tp);
    
    return tp.scm;
}

void free_scheme_time_range(struct scheme_time_range *scm)
{
    struct scheme_time_range *next;
    struct time_range *tmp, *p;
    
    while(scm != NULL)
    {
        next = scm->next;
        p=scm->p;
        while(p) {
            tmp=p->next;
            free(p);
            p=tmp;
        }
        free(scm);
        scm = next;
    }
    
    return;
}


int wlan_undo_timer_scheme(int stid)
{
    return 0;
}

int time_range_scheme_delete(char *name)
{
    return 0;
}

int time_range_scheme_create(char *name)
{
    return 0;
}

/*dow : 0~6 :-- , 8: daily, 9:weekdays, 10:weekend,*/
int time_range_scheme_add_periodic(char *name, int Dow1, int hour1, int min1,
        int Dow2, int hour2, int min2)
{
    return 0;
}


int wlan_set_timer_scheme(int stid, char *name)
{
    return 0;
}
