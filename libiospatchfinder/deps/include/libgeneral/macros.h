//
//  macros.h
//  libgeneral
//
//  Created by tihmstar on 03.05.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef macros_h
#define macros_h

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif //HAVE_CONFIG_H

#include <assert.h>

#ifndef VERSION_COMMIT_COUNT
#   define VERSION_COMMIT_COUNT "VERSION_COMMIT_COUNT_not_set"
#endif
#ifndef VERSION_COMMIT_SHA
#   define VERSION_COMMIT_SHA "VERSION_COMMIT_SHA_not_set Build: " __DATE__ " " __TIME__
#endif

#ifndef PACKAGE_NAME
#define PACKAGE_NAME "PACKAGE_NAME_not_set"
#endif //PACKAGE_NAME

#ifndef VERSION_MAJOR
#define VERSION_MAJOR "0"
#endif //VERSION_MAJOR

#ifdef DEBUG
#define BUILD_TYPE "DEBUG"
#else
#define BUILD_TYPE "RELEASE"
#endif

#define VERSION_STRING PACKAGE_NAME " version: " VERSION_MAJOR "." VERSION_COMMIT_COUNT "-" VERSION_COMMIT_SHA "-" BUILD_TYPE


// ---- functions ----

// -- logging --
#ifndef CUSTOM_LOGGING
#   ifdef HAVE_FSEEKO
#       define _LARGEFILE_SOURCE //needs to be defined before including stdio.h
#   endif
#   include <stdio.h>
#   ifndef LIBGENERAL_NO_COMPLEX_LOGGING
#       include <stdarg.h>
#       include <stdlib.h>
#       include <string.h>
static inline int libgeneral_log(const char *prefix, const char *fmt, ...){
    char *fs = NULL;
    int ret = 0;
    size_t len = 0;
    if (prefix) len += strlen(prefix);
    else len += 10; //"(NULL)"
    
    if (fmt) len += strlen(fmt);
    else len += 10; //"(NULL)"
    
    len += 2; //"\n\0"
    
    fs = (char*)malloc(len);
    if (!fs) return -1;
    
    snprintf(fs, len, "%s%s\n",prefix,fmt);
    {
        va_list ap;
        va_start(ap, fmt);
        ret = vprintf(fs, ap);
        va_end(ap);
    }
    free(fs);
    return ret;
}
#      define info(a ...) libgeneral_log("",a)
#      define warning(a ...) libgeneral_log("[WARNING] ",a)
#      define error(a ...) libgeneral_log("[Error] ",a)
#       ifdef DEBUG
//#           define debug(a ...) libgeneral_log("[DEBUG] ",a)
#           define debug(a ...)
#       else
#           define debug(a ...)
#       endif
#else
#      define info(a ...) ({printf(a),printf("\n");})
#      define warning(a ...) ({printf("[WARNING] "), printf(a),printf("\n");})
#      define error(a ...) ({printf("[Error] "),printf(a),printf("\n");})
#       ifdef DEBUG
//#           define debug(a ...) ({printf("[DEBUG] "),printf(a),printf("\n");})
#           define debug(a ...)
#       else
#           define debug(a ...)
#       endif
#   endif //LIBGENERAL_NO_COMPLEX_LOGGING
#else //CUSTOM_LOGGING
#   include CUSTOM_LOGGING
#endif //CUSTOM_LOGGING

#define safeFree(ptr) ({if (ptr) {free(ptr); ptr=NULL;}})
#define safeFreeCustom(ptr,func) ({if (ptr) {func(ptr); ptr=NULL;}})
#define safeFreeConst(ptr) ({if(ptr){void *fbuf = (void*)ptr;ptr = NULL; free(fbuf);}})
#define safeClose(fd) ({if (fd != -1) {close(fd); fd=-1;}})
#define safeCloseCustom(fd,func) ({if (fd != -1) {func(fd); fd=-1;}})


#ifdef __cplusplus
#   define safeDelete(ptr) ({if (ptr) {delete ptr; ptr=NULL;}})
#endif //__cplusplus

#ifdef __cplusplus
#   ifndef DONT_HAVE_FUNCTIONAL
#       include <functional>
#   endif
#   ifndef NO_EXCEPT_ASSURE
#       define EXCEPT_ASSURE
#   endif
#endif //__cplusplus


#ifdef STRIP_ASSURES
#   define LIBGENERAL__FILE__ "<file>"
#   define LIBGENERAL_ERRSTR(errstr ...) "<errstr>"
#else //STRIP_ASSURES
#   define LIBGENERAL__FILE__ __FILE__
#   define LIBGENERAL_ERRSTR(errstr ...) errstr
#endif //STRIP_ASSURES

// -- assure --
#define cassure(a) do{ if ((a) == 0){err=__LINE__; goto error;} }while(0)
#define cretassure(cond, errstr ...) do{ if ((cond) == 0){err=__LINE__;error(LIBGENERAL_ERRSTR(errstr)); goto error;} }while(0)
#define creterror(errstr ...) do{error(LIBGENERAL_ERRSTR(errstr));err=__LINE__; goto error; }while(0)

#ifdef EXCEPT_ASSURE
#   include <libgeneral/exception.hpp>
//assure cpp
#   define assure(cond) do{ if ((cond) == 0) throw tihmstar::EXPECTIONNAME(VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA, __LINE__, LIBGENERAL__FILE__, LIBGENERAL_ERRSTR("assure failed")); } while(0)
#   define retassure(cond, errstr ...) do{ if ((cond) == 0) throw tihmstar::EXPECTIONNAME(VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA, __LINE__,LIBGENERAL__FILE__,LIBGENERAL_ERRSTR(errstr)); } while(0)
#   define customassure(custom_except, cond) do{ if ((cond) == 0) throw tihmstar::custom_except(VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA, __LINE__, LIBGENERAL__FILE__, LIBGENERAL_ERRSTR("assure failed")); } while(0)
#   define retcustomassure(custom_except, cond, errstr ...) do{ if ((cond) == 0) throw tihmstar::custom_except(VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA, __LINE__, LIBGENERAL__FILE__, LIBGENERAL_ERRSTR(errstr)); } while(0)
#   define reterror(errstr ...) do{ throw tihmstar::EXPECTIONNAME(VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA, __LINE__, LIBGENERAL__FILE__, LIBGENERAL_ERRSTR(errstr)); } while(0)
#   define retcustomerror(custom_except,errstr ...) do{ throw tihmstar::custom_except(VERSION_COMMIT_COUNT, VERSION_COMMIT_SHA, __LINE__, LIBGENERAL__FILE__, LIBGENERAL_ERRSTR(errstr)); } while(0)
#   define doassure(cond,code) do {if (!(cond)){(code);assure(cond);}} while(0)

//DEBUG assures
#ifdef DEBUG
#   define assure_dbg(cond) assure(cond)
#   define retassure_dbg(cond, errstr ...) retassure(cond, errstr)
#   define customassure_dbg(custom_except, cond) customassure(custom_except, cond)
#   define retcustomassure_dbg(custom_except, cond, errstr ...) retcustomassure(custom_except, cond, errstr)
#   define reterror_dbg(errstr ...) reterror(errstr)
#   define retcustomerror_dbg(custom_except,errstr ...) retcustomerror(custom_except,errstr)
#else
#   define assure_dbg(cond) ((void)(cond))
#   define retassure_dbg(cond, errstr ...) ((void)(cond))
#   define customassure_dbg(custom_except, cond) ((void)(cond))
#   define retcustomassure_dbg(custom_except, cond, errstr ...) ((void)(cond))
#   define reterror_dbg(errstr ...)
#   define retcustomerror_dbg(custom_except,errstr ...)
#endif


// //more cpp assure
#   ifndef EXPECTIONNAME
#       define EXPECTIONNAME exception
#   endif

#   if !0 //LIBGENERAL_CLEANUP_IS_DISABLED
#       ifndef DONT_HAVE_FUNCTIONAL
class guard{
    std::function<void()> _f;
public:
    guard(std::function<void()> cleanup) : _f(cleanup) {}
    guard(const guard&) = delete; //delete copy constructor
    guard(guard &&o) = delete; //move constructor
    
    ~guard(){_f();}
};
#           define cleanup(f) guard _cleanup(f);
#       endif //DONT_HAVE_FUNCTIONAL
#   endif //LIBGENERAL_CLEANUP_IS_DISABLED
#endif //EXCEPT_ASSURE

#ifdef XCODE
#   define MAINFUNCTION \
        int main(int argc, const char * argv[]) {  \
            int main_r(int argc, const char * argv[]); \
            return main_r(argc, argv); \
        }
#   define CATCHFUNC(f) f()
#else
#   define MAINFUNCTION \
        int main(int argc, const char * argv[]) {  \
            int main_r(int argc, const char * argv[]); \
            try { \
                return main_r(argc, argv); \
            } catch (tihmstar::exception &e) { \
                error("%s: failed with exception:\n%s",PACKAGE_NAME,e.dumpStr().c_str()); \
                return e.code(); \
            } catch (std::exception &e) { \
                error("%s: failed with std::exception (%s)",PACKAGE_NAME,e.what()); \
                exit(-1); \
            } \
        }
#   define CATCHFUNC(f) \
        do{ \
            try { \
                f(); \
            } catch (tihmstar::exception &e) { \
                error("%s: failed with exception:\n%s",PACKAGE_NAME,e.dumpStr().c_str()); \
                exit(e.code()); \
            } catch (std::exception &e) { \
                error("%s: failed with std::exception (%s)",PACKAGE_NAME,e.what()); \
                exit(-1); \
            } \
        }while (0)
#endif

#endif /* macros_h */
