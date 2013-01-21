#ifndef _XBL_LOG_H_
#define _XBL_LOG_H_

void err_dump(const char *, ...);
void err_msg(const char *, ...);
void err_quit(const char *, ...);
void err_exit(int, const char *, ...);
void err_ret(const char *, ...);
void err_sys(const char *, ...);

void log_open(const char *, int, int);
void log_msg(const char *, ...);
void log_quit(const char *, ...);
void log_ret(const char *, ...);
void log_sys(const char *, ...);

#endif /* _XBL_LOG_H_ */
