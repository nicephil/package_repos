#ifndef __TIME_RANGE_SERVICES_H_
#define __TIME_RANGE_SERVICES_H_

#include <time.h>


#define CFG_TIME_RANGE_PACKAGE "time_range"
#define CFG_TIME_RANGE_PERIOD_LIST "period_list"
#define CFG_TIME_RANGE_ABSTIME "abstime"
#define CFG_TIME_RANGE_SSID "ssid_time_range"

//#define SCHEME_TIME_RANGE_MAXSIZE 16
//#define PERIODIC_TIME_RANGE_MAXSIZE 16
#define SCHEME_TIME_RANGE_NAME_MAXSIZE 32

struct time_range {
    struct time_range *next;
    struct tm start;
    struct tm end;
};


struct scheme_time_range {
    struct scheme_time_range *next;
    char name[SCHEME_TIME_RANGE_NAME_MAXSIZE+1];
    struct time_range a;
    int count;
    struct time_range *p; /*need auto size*/
};

struct action_time_range {
    int option;     /*add or del*/
    int type;       /*period or absolute*/
    char name[SCHEME_TIME_RANGE_NAME_MAXSIZE+1];
    struct time_range t;
};

struct reset_time_range {
    int option;     /*should set reset*/
    char name[SCHEME_TIME_RANGE_NAME_MAXSIZE+1]; /*if no name set , do reset for all scheme*/
    //struct scheme_time_range s;
};

struct get_time_range{
    char name[SCHEME_TIME_RANGE_NAME_MAXSIZE+1];
    struct scheme_time_range *scm;
};



extern struct scheme_time_range * get_time_range_byname(char *name);
extern void free_scheme_time_range(struct scheme_time_range *scm);
extern int wlan_undo_timer_scheme(int stid);
extern int time_range_scheme_delete(char *name);
extern int time_range_scheme_create(char *name);
/*dow : 0~6 :-- , 8: daily, 9:weekdays, 10:weekend,*/
extern int time_range_scheme_add_periodic(char *name, int Dow1, int hour1, int min1,
        int Dow2, int hour2, int min2);

int wlan_set_timer_scheme(int stid, char *name);

#endif /* __TIME_RANGE_SERVICES_H_ */
