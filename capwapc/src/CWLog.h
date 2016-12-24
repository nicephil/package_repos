/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	       *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                *
 *                                                                                         *
 * You should have received a copy of the GNU General Public License along with this       *
 * program; if not, write to the:                                                          *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                    *
 * MA  02111-1307, USA.                                                                    *
 *                                                                                         *
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *  
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/


#ifndef __CAPWAP_CWLog_HEADER__
#define __CAPWAP_CWLog_HEADER__

extern char gLogFileName[];
extern int log_id;
#if 1
void CWVLog(const char *format, va_list args);

void CWLog(const char *format, ...);
void CWDebugLog(const char *format, ...);

#define CWDebugLog_E(fmt, ...) CWLog(fmt, ##__VA_ARGS__)
#define CWDebugLog_F(fmt, ...) CWLog(fmt, ##__VA_ARGS__)
#define CWDebugLog_D(fmt, ...) CWDebugLog(fmt, ##__VA_ARGS__)
#else
#define CWLog(fmt, ...) zlog(log_id, LOG_INFO, fmt, ##__VA_ARGS__)
#define CWDebugLog(fmt, ...) zlog(log_id, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define CWDebugLog_E(fmt, ...) zlog(log_id, DEBUG_EXCEPT, fmt, ##__VA_ARGS__)
#define CWDebugLog_F(fmt, ...) zlog(log_id, DEBUG_FLOW, fmt, ##__VA_ARGS__)
#define CWDebugLog_D(fmt, ...) zlog(log_id, DEBUG_DETAIL, fmt, ##__VA_ARGS__)
#endif
void CWLogInitFile(char *fileName);

#endif
